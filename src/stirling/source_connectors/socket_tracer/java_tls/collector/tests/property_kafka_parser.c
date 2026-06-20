/* Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
/* Property/round-trip tester for kafka_parser.h: build a random Produce frame
 * (flexible v9 or non-flexible v7, random codec, random records of random size)
 * -> parse -> assert the decoded records match what was built. Under ASan+UBSan.
 * Property: parse(build(records)) yields exactly those record values, for all
 * codecs and both wire encodings. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#include <zstd.h>
#include <snappy-c.h>
extern unsigned long LZ4F_compressFrameBound(unsigned long, const void*);
extern unsigned long LZ4F_compressFrame(void*, unsigned long, const void*, unsigned long, const void*);
extern unsigned LZ4F_isError(unsigned long);
#include "kafka_parser.h"

static long checks=0, fails=0;
#define CHK(c,fmt,...) do{checks++; if(!(c)){fails++; printf("  FAIL["#c"]: " fmt "\n",##__VA_ARGS__);}}while(0)

static uint64_t rng=0xC0FFEE;
static uint64_t xr(){ rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }

static int gz(const uint8_t*in,int n,uint8_t*o,int c){z_stream z;memset(&z,0,sizeof z);if(deflateInit2(&z,6,Z_DEFLATED,15+16,8,Z_DEFAULT_STRATEGY)!=Z_OK)return -1;z.next_in=(Bytef*)in;z.avail_in=n;z.next_out=o;z.avail_out=c;deflate(&z,Z_FINISH);int r=z.total_out;deflateEnd(&z);return r;}
static int zst(const uint8_t*in,int n,uint8_t*o,int c){size_t r=ZSTD_compress(o,c,in,n,3);return ZSTD_isError(r)?-1:(int)r;}
static int lz4f(const uint8_t*in,int n,uint8_t*o,int c){unsigned long r=LZ4F_compressFrame(o,c,in,n,NULL);return LZ4F_isError(r)?-1:(int)r;}
static int snp(const uint8_t*in,int n,uint8_t*o,int c){size_t oo=c;return snappy_compress((const char*)in,n,(char*)o,&oo)==SNAPPY_OK?(int)oo:-1;}
static int comp(int codec,const uint8_t*in,int n,uint8_t*o,int c){
  switch(codec){case 0:memcpy(o,in,n);return n;case 1:return gz(in,n,o,c);case 2:return snp(in,n,o,c);
  case 3:return lz4f(in,n,o,c);case 4:return zst(in,n,o,c);} return -1; }

static int wv(uint8_t*b,int64_t v){uint64_t u=((uint64_t)v<<1)^(v>>63);int i=0;do{uint8_t x=u&0x7f;u>>=7;if(u)x|=0x80;b[i++]=x;}while(u);return i;}
static int wuv(uint8_t*b,uint32_t v){int i=0;do{uint8_t x=v&0x7f;v>>=7;if(v)x|=0x80;b[i++]=x;}while(v);return i;}
static void p16(uint8_t*b,int v){b[0]=v>>8;b[1]=v;} static void p32(uint8_t*b,uint32_t v){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;} static void p64(uint8_t*b,uint64_t v){for(int i=0;i<8;i++)b[i]=v>>(56-8*i);}

/* expected records */
#define MAXR 12
static struct { int vlen; uint8_t val[4096]; } exp_[MAXR]; static int nexp;
static int got_n; static struct { int vlen; uint8_t val[4096]; } got_[MAXR];
static void cb(void*c,const char*t,int32_t p,const uint8_t*k,int kl,const uint8_t*v,int vl){
  (void)c;(void)t;(void)p;(void)k;(void)kl; if(got_n>=MAXR){got_n++;return;}
  int m=vl<4096?vl:4096; got_[got_n].vlen=vl; if(v&&m>0)memcpy(got_[got_n].val,v,m); got_n++;
}

static int wrec(uint8_t*b,const uint8_t*val,int vl){
  uint8_t body[5000]; int o=0; body[o++]=0; o+=wv(body+o,0); o+=wv(body+o,0); o+=wv(body+o,-1);
  o+=wv(body+o,vl); memcpy(body+o,val,vl); o+=vl; o+=wv(body+o,0);
  int hl=wv(b,o); memcpy(b+hl,body,o); return hl+o;
}
static int build_batch(uint8_t*out,int codec){
  uint8_t recs[60000]; int rl=0;
  for(int i=0;i<nexp;i++) rl+=wrec(recs+rl,exp_[i].val,exp_[i].vlen);
  uint8_t blob[70000]; int blen=comp(codec,recs,rl,blob,sizeof blob); if(blen<0)return -1;
  int o=0; p64(out+o,0);o+=8; int blp=o;o+=4; p32(out+o,0);o+=4; out[o++]=2; p32(out+o,0);o+=4;
  p16(out+o,codec&7);o+=2; p32(out+o,nexp-1);o+=4; p64(out+o,0);o+=8;p64(out+o,0);o+=8;
  p64(out+o,-1);o+=8;p16(out+o,-1);o+=2;p32(out+o,-1);o+=4; p32(out+o,nexp);o+=4;
  memcpy(out+o,blob,blen);o+=blen; p32(out+blp,o-(blp+4)); return o;
}

static void one(int flexible,int codec){
  nexp=1+(int)(xr()%MAXR); got_n=0;
  for(int i=0;i<nexp;i++){ int vl=(int)(xr()% (i==0?1500:300)); exp_[i].vlen=vl;
    for(int j=0;j<vl;j++) exp_[i].val[j]=(uint8_t)(xr()); }
  uint8_t f[200000]; int o=0; int ver=flexible?9:7;
  p16(f+o,0);o+=2;p16(f+o,ver);o+=2;p32(f+o,7);o+=4;            /* api,ver,corr */
  p16(f+o,1);o+=2;f[o++]='c';                                   /* client_id (regular) */
  if(flexible) o+=wuv(f+o,0);                                   /* header tags */
  /* body */
  if(flexible){ o+=wuv(f+o,0); } else { p16(f+o,-1);o+=2; }     /* transactional_id (v>=3) */
  p16(f+o,-1);o+=2; p32(f+o,0);o+=4;                            /* acks, timeout */
  if(flexible) o+=wuv(f+o,2); else { p32(f+o,1);o+=4; }              /* topics count */
  const char*tp="t"; if(flexible){o+=wuv(f+o,strlen(tp)+1);} else {p16(f+o,strlen(tp));o+=2;} memcpy(f+o,tp,strlen(tp));o+=strlen(tp);
  if(flexible) o+=wuv(f+o,2); else { p32(f+o,1);o+=4; }              /* partitions count */
  p32(f+o,3);o+=4;                                             /* partition index */
  uint8_t batch[120000]; int blen=build_batch(batch,codec); if(blen<0){return;}
  if(flexible) o+=wuv(f+o,blen+1); else { p32(f+o,blen);o+=4; }      /* records size */
  memcpy(f+o,batch,blen);o+=blen;
  if(flexible){ o+=wuv(f+o,0); o+=wuv(f+o,0); }                 /* partition + topic tags */

  kafka_req_hdr_t h; int hr=kafka_parse_request_header(f,o,&h);
  CHK(hr==0 && h.api_key==0 && h.api_version==ver, "header parse flex=%d codec=%d",flexible,codec);
  kafka_parse_produce(f,o,&h,cb,NULL);
  CHK(got_n==nexp, "record count got=%d want=%d flex=%d codec=%d",got_n,nexp,flexible,codec);
  int lim=got_n<nexp?got_n:nexp;
  for(int i=0;i<lim;i++){
    CHK(got_[i].vlen==exp_[i].vlen, "rec%d vlen got=%d want=%d flex=%d codec=%d",i,got_[i].vlen,exp_[i].vlen,flexible,codec);
    if(got_[i].vlen==exp_[i].vlen)
      CHK(memcmp(got_[i].val,exp_[i].val,exp_[i].vlen)==0,"rec%d bytes flex=%d codec=%d",i,flexible,codec);
  }
}

int main(int argc,char**argv){
  int N=argc>1?atoi(argv[1]):20000;
  for(int i=0;i<N;i++){ int flex=xr()&1; int codec=(int)(xr()%5); one(flex,codec); }
  printf("%ld checks, %ld failures\n",checks,fails);
  printf(fails?"RESULT: FAIL\n":"RESULT: PASS\n"); return fails?1:0;
}
