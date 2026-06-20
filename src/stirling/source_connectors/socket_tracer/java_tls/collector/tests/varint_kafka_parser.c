/* Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>
#include <snappy-c.h>
extern unsigned long LZ4F_compressFrameBound(unsigned long,const void*);
extern unsigned long LZ4F_compressFrame(void*,unsigned long,const void*,unsigned long,const void*);
extern unsigned LZ4F_isError(unsigned long);
#include "kafka_parser.h"
/* standard encoders */
static int enc_uvarint(uint8_t*b,uint32_t v){int i=0;do{uint8_t x=v&0x7f;v>>=7;if(v)x|=0x80;b[i++]=x;}while(v);return i;}
static int enc_varint(uint8_t*b,int32_t v){return enc_uvarint(b,((uint32_t)v<<1)^(uint32_t)(v>>31));}
static int enc_varlong(uint8_t*b,int64_t v){uint64_t u=((uint64_t)v<<1)^(uint64_t)(v>>63);int i=0;do{uint8_t x=u&0x7f;u>>=7;if(u)x|=0x80;b[i++]=x;}while(u);return i;}
static long ch=0,f=0;
#define EQ(a,b,m,...) do{ch++; if((a)!=(b)){f++; printf("FAIL %s: " m "\n",#a,##__VA_ARGS__);}}while(0)
static uint64_t rng=0x9e3779b97f4a7c15ULL; static uint64_t xr(){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
static void t_uv(uint32_t v){uint8_t b[8];int n=enc_uvarint(b,v);kd_t d;kd_init(&d,b,n);uint32_t g=kd_uvarint(&d);EQ(g,v,"uvarint %u->%u",v,g);EQ(d.err,0,"uv err v=%u",v);}
static void t_vi(int32_t v){uint8_t b[8];int n=enc_varint(b,v);kd_t d;kd_init(&d,b,n);int32_t g=kd_varint(&d);EQ(g,v,"varint %d->%d",v,g);EQ(d.err,0,"vi err v=%d",v);}
static void t_vl(int64_t v){uint8_t b[12];int n=enc_varlong(b,v);kd_t d;kd_init(&d,b,n);int64_t g=kd_varlong(&d);EQ((long long)g,(long long)v,"varlong %lld->%lld",(long long)v,(long long)g);EQ(d.err,0,"vl err");}
int main(){
  uint32_t uvb[]={0,1,127,128,16383,16384,2097151,2097152,268435455,268435456,0x7fffffff,0x80000000,0xffffffff};
  for(unsigned i=0;i<sizeof uvb/sizeof*uvb;i++) t_uv(uvb[i]);
  int32_t vib[]={0,1,-1,63,-64,INT32_MAX,INT32_MIN,12345,-12345};
  for(unsigned i=0;i<sizeof vib/sizeof*vib;i++) t_vi(vib[i]);
  int64_t vlb[]={0,1,-1,INT64_MAX,INT64_MIN,((int64_t)1<<40),(-((int64_t)1<<40))};
  for(unsigned i=0;i<sizeof vlb/sizeof*vlb;i++) t_vl(vlb[i]);
  for(int i=0;i<2000000;i++){ t_uv((uint32_t)xr()); t_vi((int32_t)xr()); t_vl((int64_t)xr()); }
  printf("%ld checks, %ld failures\n",ch,f); printf(f?"RESULT: FAIL\n":"RESULT: PASS\n"); return f?1:0;
}
