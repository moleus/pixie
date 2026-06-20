/* Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
/* Local test harness for kafka_parser.h: codec round-trips (incl. multi-block)
 * and a full Produce-frame parse. Build: see build at bottom of this dir's run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#include <zstd.h>
#include <snappy-c.h>

/* compress-side lz4 frame API (decompress side is declared by the header) */
extern unsigned long LZ4F_compressFrameBound(unsigned long srcSize, const void* prefs);
extern unsigned long LZ4F_compressFrame(void* dst, unsigned long dstCap,
                                        const void* src, unsigned long srcSize, const void* prefs);
extern unsigned LZ4F_isError(unsigned long);

#include "kafka_parser.h"

static int failures = 0, checks = 0;
#define CHECK(cond, msg) do{ checks++; if(!(cond)){ failures++; \
  printf("  FAIL: %s\n", msg);} else { printf("  ok:   %s\n", msg);} }while(0)

/* ---- compressors (produce inputs that kafka_decompress must invert) ---- */
static int gz(const uint8_t*in,int n,uint8_t*out,int cap){
  z_stream z; memset(&z,0,sizeof z);
  if(deflateInit2(&z,6,Z_DEFLATED,15+16,8,Z_DEFAULT_STRATEGY)!=Z_OK)return -1;
  z.next_in=(Bytef*)in; z.avail_in=n; z.next_out=out; z.avail_out=cap;
  deflate(&z,Z_FINISH); int r=z.total_out; deflateEnd(&z); return r;
}
static int zst(const uint8_t*in,int n,uint8_t*out,int cap){
  size_t r=ZSTD_compress(out,cap,in,n,3); return ZSTD_isError(r)?-1:(int)r; }
static int lz4f(const uint8_t*in,int n,uint8_t*out,int cap){
  unsigned long r=LZ4F_compressFrame(out,cap,in,n,NULL); return LZ4F_isError(r)?-1:(int)r; }
static int snap_raw(const uint8_t*in,int n,uint8_t*out,int cap){
  size_t o=cap; return snappy_compress((const char*)in,n,(char*)out,&o)==SNAPPY_OK?(int)o:-1; }
/* xerial: 8B magic + i32 ver + i32 compat, then [i32 blocklen][snappy block]... */
static int snap_xerial(const uint8_t*in,int n,uint8_t*out,int cap,int blocksz){
  static const uint8_t magic[8]={0x82,'S','N','A','P','P','Y',0};
  int o=0; memcpy(out,magic,8); o=8;
  out[o++]=0;out[o++]=0;out[o++]=0;out[o++]=1; /* version */
  out[o++]=0;out[o++]=0;out[o++]=0;out[o++]=1; /* compat */
  for(int p=0;p<n;p+=blocksz){
    int chunk=(n-p<blocksz)?(n-p):blocksz;
    size_t bo=cap-o-4;
    if(snappy_compress((const char*)in+p,chunk,(char*)out+o+4,&bo)!=SNAPPY_OK)return -1;
    out[o]=(bo>>24)&0xff;out[o+1]=(bo>>16)&0xff;out[o+2]=(bo>>8)&0xff;out[o+3]=bo&0xff;
    o+=4+(int)bo;
  }
  return o;
}

static void roundtrip(const char*name,int codec,
                      int(*comp)(const uint8_t*,int,uint8_t*,int),
                      const uint8_t*plain,int n){
  static uint8_t cbuf[1<<21], dbuf[1<<21];
  int clen=comp(plain,n,cbuf,sizeof cbuf);
  char m[128];
  if(clen<=0){ snprintf(m,sizeof m,"%s: compress failed",name); CHECK(0,m); return; }
  int dlen=kafka_decompress(codec,cbuf,clen,dbuf,sizeof dbuf);
  snprintf(m,sizeof m,"%s: decompress len %d == %d",name,dlen,n);
  CHECK(dlen==n,m);
  snprintf(m,sizeof m,"%s: bytes match",name);
  CHECK(dlen==n && memcmp(dbuf,plain,n)==0,m);
}

/* ---- Produce-frame builder + parse test ---- */
typedef struct { char topic[64]; int part; int klen,vlen; char val[64]; } rec_t;
static rec_t got[16]; static int ngot=0;
static void rec_cb(void*ctx,const char*topic,int32_t part,const uint8_t*k,int kl,const uint8_t*v,int vl){
  (void)ctx; if(ngot>=16)return; rec_t*r=&got[ngot++];
  snprintf(r->topic,sizeof r->topic,"%s",topic); r->part=part; r->klen=kl; r->vlen=vl;
  int m=vl<63?vl:63; if(v&&m>0)memcpy(r->val,v,m); r->val[m>0?m:0]=0;
}
/* varint (zigzag) writer */
static int wv(uint8_t*b,int64_t v){ uint64_t u=((uint64_t)v<<1)^(v>>63); int i=0;
  do{ uint8_t x=u&0x7f; u>>=7; if(u)x|=0x80; b[i++]=x; }while(u); return i; }
static int wrec(uint8_t*b,const char*val){ /* one record, null key */
  int vl=strlen(val); uint8_t body[256]; int o=0;
  body[o++]=0;                 /* attributes */
  o+=wv(body+o,0);             /* timestamp_delta */
  o+=wv(body+o,0);             /* offset_delta */
  o+=wv(body+o,-1);            /* key len = null */
  o+=wv(body+o,vl); memcpy(body+o,val,vl); o+=vl;  /* value */
  o+=wv(body+o,0);             /* header count */
  int hl=wv(b,o);              /* record length prefix */
  memcpy(b+hl,body,o); return hl+o;
}
static void p_i16(uint8_t*b,int v){b[0]=v>>8;b[1]=v;} static void p_i32(uint8_t*b,uint32_t v){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;}
static void p_i64(uint8_t*b,uint64_t v){for(int i=0;i<8;i++)b[i]=v>>(56-8*i);}

/* build a record batch (magic v2) for `recs` records, codec applied to blob */
static int build_batch(uint8_t*out,int codec,int(*comp)(const uint8_t*,int,uint8_t*,int),
                       const char**vals,int nrec){
  uint8_t recs[1024]; int rl=0;
  for(int i=0;i<nrec;i++) rl+=wrec(recs+rl,vals[i]);
  uint8_t blob[2048]; int blen;
  if(codec==0){ memcpy(blob,recs,rl); blen=rl; }
  else { blen=comp(recs,rl,blob,sizeof blob); if(blen<=0)return -1; }
  int o=0; p_i64(out+o,0);o+=8;            /* base_offset */
  int blp=o; o+=4;                          /* batch_length placeholder */
  p_i32(out+o,0);o+=4;                      /* partition_leader_epoch */
  out[o++]=2;                               /* magic */
  p_i32(out+o,0);o+=4;                      /* crc */
  p_i16(out+o,codec&0x07);o+=2;             /* attributes */
  p_i32(out+o,nrec-1);o+=4;                 /* last_offset_delta */
  p_i64(out+o,0);o+=8; p_i64(out+o,0);o+=8; /* first/max ts */
  p_i64(out+o,-1);o+=8;                     /* producer_id */
  p_i16(out+o,-1);o+=2;                     /* producer_epoch */
  p_i32(out+o,-1);o+=4;                     /* base_sequence */
  p_i32(out+o,nrec);o+=4;                   /* record count */
  memcpy(out+o,blob,blen); o+=blen;
  p_i32(out+blp,o-(blp+4));                 /* batch_length = bytes after it */
  return o;
}
/* uvarint writer (compact lengths) */
static int wuv(uint8_t*b,uint32_t v){int i=0;do{uint8_t x=v&0x7f;v>>=7;if(v)x|=0x80;b[i++]=x;}while(v);return i;}

static void produce_test(const char*name,int codec,int(*comp)(const uint8_t*,int,uint8_t*,int)){
  const char*vals[2]={"hello-kafka","second-record"};
  uint8_t frame[4096]; int o=0;
  /* header: api_key=0, ver=9 (flexible), corr=7, client_id="c", header tags=0 */
  p_i16(frame+o,0);o+=2; p_i16(frame+o,9);o+=2; p_i32(frame+o,7);o+=4;
  p_i16(frame+o,1);o+=2; frame[o++]='c';        /* client_id regular string */
  o+=wuv(frame+o,0);                            /* header v2 tagged fields */
  /* body (flexible) */
  o+=wuv(frame+o,0);                            /* transactional_id = null (compact) */
  p_i16(frame+o,-1);o+=2;                       /* acks */
  p_i32(frame+o,30000);o+=4;                    /* timeout_ms */
  o+=wuv(frame+o,2);                            /* topics: count+1 */
  const char*tp="orders"; o+=wuv(frame+o,strlen(tp)+1); memcpy(frame+o,tp,strlen(tp)); o+=strlen(tp);
  o+=wuv(frame+o,2);                            /* partitions: count+1 */
  p_i32(frame+o,3);o+=4;                         /* partition index */
  uint8_t batch[4096]; int blen=build_batch(batch,codec,comp,vals,2);
  if(blen<0){ char m[64]; snprintf(m,sizeof m,"%s: batch build failed",name); CHECK(0,m); return;}
  o+=wuv(frame+o,blen+1);                        /* records compact bytes: len+1 */
  memcpy(frame+o,batch,blen); o+=blen;
  o+=wuv(frame+o,0);                            /* partition tags */
  o+=wuv(frame+o,0);                            /* topic tags */

  ngot=0;
  kafka_req_hdr_t h; int hr=kafka_parse_request_header(frame,o,&h);
  char m[128];
  snprintf(m,sizeof m,"%s: header api=%d ver=%d client=%s",name,h.api_key,h.api_version,h.client_id);
  CHECK(hr==0 && h.api_key==0 && h.api_version==9 && strcmp(h.client_id,"c")==0,m);
  kafka_parse_produce(frame,o,&h,rec_cb,NULL);
  snprintf(m,sizeof m,"%s: decoded %d records (want 2)",name,ngot);
  CHECK(ngot==2,m);
  if(ngot>=1){ snprintf(m,sizeof m,"%s: rec0 topic=%s part=%d val=%s",name,got[0].topic,got[0].part,got[0].val);
    CHECK(strcmp(got[0].topic,"orders")==0 && got[0].part==3 && strcmp(got[0].val,"hello-kafka")==0,m);}
  if(ngot>=2){ snprintf(m,sizeof m,"%s: rec1 val=%s",name,got[1].val);
    CHECK(strcmp(got[1].val,"second-record")==0,m);}
}

int main(void){
  /* plaintext: large + compressible to force multi-block frames */
  static uint8_t plain[300000];
  for(int i=0;i<(int)sizeof plain;i++) plain[i]=(uint8_t)('A'+(i*7+ (i/64))%26);

  printf("== decompression round-trips ==\n");
  roundtrip("gzip",        1, gz,      plain, sizeof plain);
  roundtrip("zstd",        4, zst,     plain, sizeof plain);
  roundtrip("lz4-frame",   3, lz4f,    plain, sizeof plain);   /* multi-block */
  roundtrip("snappy-raw",  2, snap_raw,plain, 60000);          /* raw fallback */
  /* xerial multi-block via wrapper */
  { static uint8_t cb[1<<21],db[1<<21]; int cl=snap_xerial(plain,sizeof plain,cb,sizeof cb,32768);
    int dl=kafka_decompress(2,cb,cl,db,sizeof db);
    CHECK(dl==(int)sizeof plain && memcmp(db,plain,sizeof plain)==0,"snappy-xerial multi-block: round-trip"); }

  printf("== full Produce-frame parse ==\n");
  produce_test("produce-uncompressed",0,NULL);
  produce_test("produce-gzip",1,gz);
  produce_test("produce-zstd",4,zst);
  produce_test("produce-lz4",3,lz4f);
  produce_test("produce-snappy",2,snap_raw);

  printf("\n%d checks, %d failures\n", checks, failures);
  printf(failures? "RESULT: FAIL\n":"RESULT: PASS\n");
  return failures?1:0;
}
