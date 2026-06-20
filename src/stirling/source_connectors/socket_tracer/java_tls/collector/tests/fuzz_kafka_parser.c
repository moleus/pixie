/* Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
/* Adversarial / memory-safety harness for kafka_parser.h, run under ASan.
 * Feeds truncated valid frames, random bytes, and crafted-malformed inputs to
 * every public entry point; ASan flags any out-of-bounds access. */
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

static long records_seen=0;
static void cb(void*c,const char*t,int32_t p,const uint8_t*k,int kl,const uint8_t*v,int vl){
  (void)c;(void)p; volatile char sink=0;
  if(t) sink^=t[0];
  for(int i=0;i<kl;i++) sink^=k[i];   /* touch reported key bytes */
  for(int i=0;i<vl;i++) sink^=v[i];   /* touch reported value bytes (catches bad len) */
  (void)sink; records_seen++;
}

/* minimal valid-ish produce v9 frame builder (subset of test_kafka.c) */
static int wv(uint8_t*b,int64_t v){uint64_t u=((uint64_t)v<<1)^(v>>63);int i=0;do{uint8_t x=u&0x7f;u>>=7;if(u)x|=0x80;b[i++]=x;}while(u);return i;}
static int wuv(uint8_t*b,uint32_t v){int i=0;do{uint8_t x=v&0x7f;v>>=7;if(v)x|=0x80;b[i++]=x;}while(v);return i;}
static void p16(uint8_t*b,int v){b[0]=v>>8;b[1]=v;} static void p32(uint8_t*b,uint32_t v){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;} static void p64(uint8_t*b,uint64_t v){for(int i=0;i<8;i++)b[i]=v>>(56-8*i);}
static int build_produce(uint8_t*f){
  int o=0; p16(f+o,0);o+=2;p16(f+o,9);o+=2;p32(f+o,7);o+=4; p16(f+o,1);o+=2;f[o++]='c'; o+=wuv(f+o,0);
  o+=wuv(f+o,0); p16(f+o,-1);o+=2; p32(f+o,30000);o+=4; o+=wuv(f+o,2);
  const char*tp="orders"; o+=wuv(f+o,strlen(tp)+1);memcpy(f+o,tp,strlen(tp));o+=strlen(tp); o+=wuv(f+o,2);
  p32(f+o,3);o+=4;
  uint8_t rb[256]; int rl=0; rb[rl++]=0;rl+=wv(rb+rl,0);rl+=wv(rb+rl,0);rl+=wv(rb+rl,-1);
  const char*val="payload"; rl+=wv(rb+rl,strlen(val));memcpy(rb+rl,val,strlen(val));rl+=strlen(val);rl+=wv(rb+rl,0);
  uint8_t batch[512]; int b=0; p64(batch+b,0);b+=8; int blp=b;b+=4; p32(batch+b,0);b+=4; batch[b++]=2;
  p32(batch+b,0);b+=4; p16(batch+b,0);b+=2; p32(batch+b,0);b+=4; p64(batch+b,0);b+=8;p64(batch+b,0);b+=8;
  p64(batch+b,-1);b+=8;p16(batch+b,-1);b+=2;p32(batch+b,-1);b+=4; p32(batch+b,1);b+=4;
  int hl=wv(batch+b,rl); memcpy(batch+b+hl,rb,rl); b+=hl+rl; p32(batch+blp,b-(blp+4));
  o+=wuv(f+o,b+1); memcpy(f+o,batch,b);o+=b; o+=wuv(f+o,0);o+=wuv(f+o,0);
  return o;
}

static unsigned long rng=0x12345;
static unsigned long rr(){ rng=rng*6364136223846793005UL+1442695040888963407UL; return rng>>17; }

static int ITERS=20000;
int main(int argc,char**argv){ if(argc>1)ITERS=atoi(argv[1]);
  uint8_t f[4096]; int n=build_produce(f);
  printf("valid produce frame: %d bytes\n", n);

  /* 1) truncate the valid frame at every prefix length */
  for(int L=0;L<=n;L++){ kafka_req_hdr_t h; if(kafka_parse_request_header(f,L,&h)==0) kafka_parse_produce(f,L,&h,cb,NULL); }
  /* also drive it as a fetch response at every length */
  for(int L=0;L<=n;L++){ kafka_req_hdr_t h; memset(&h,0,sizeof h); kafka_parse_fetch_response(f,L,12,cb,NULL,&h); }

  /* 2) byte-flip fuzz: mutate the valid frame and parse, many iterations */
  for(int it=0;it<ITERS;it++){
    uint8_t g[4096]; memcpy(g,f,n); int nn=n;
    int muts=1+rr()%6; for(int m=0;m<muts;m++){ g[rr()%nn]^=(uint8_t)(1<<(rr()%8)); }
    if(rr()%4==0) nn=rr()%(n+1);            /* sometimes truncate */
    kafka_req_hdr_t h; if(kafka_parse_request_header(g,nn,&h)==0) kafka_parse_produce(g,nn,&h,cb,NULL);
    memset(&h,0,sizeof h); kafka_parse_fetch_response(g,nn,(int16_t)(rr()%18),cb,NULL,&h);
  }

  /* 3) pure random buffers of random lengths */
  for(int it=0;it<ITERS;it++){
    uint8_t g[512]; int nn=rr()%(int)sizeof g; for(int i=0;i<nn;i++)g[i]=(uint8_t)rr();
    kafka_req_hdr_t h; if(kafka_parse_request_header(g,nn,&h)==0) kafka_parse_produce(g,nn,&h,cb,NULL);
    memset(&h,0,sizeof h); kafka_parse_fetch_response(g,nn,(int16_t)(rr()%18),cb,NULL,&h);
  }

  /* 4) decompressor abuse: malformed xerial with huge block length, junk inputs */
  { uint8_t x[64]={0x82,'S','N','A','P','P','Y',0, 0,0,0,1, 0,0,0,1, 0x7f,0xff,0xff,0xff}; /* blk=2GB */
    uint8_t out[4096]; kafka_decompress(2,x,sizeof x,out,sizeof out); }
  for(int it=0;it<(ITERS/4>0?ITERS/4:1);it++){
    uint8_t in[256]; int nn=rr()%(int)sizeof in; for(int i=0;i<nn;i++)in[i]=(uint8_t)rr();
    uint8_t out[4096]; int codec=1+rr()%4; kafka_decompress(codec,in,nn,out,sizeof out);
  }

  printf("records_seen=%ld\nFUZZ DONE (ASan clean if no abort above)\n", records_seen);
  return 0;
}
