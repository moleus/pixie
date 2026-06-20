/* Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
/* Synthetic JSSE caller: emits a real length-prefixed Kafka Produce frame
 * through pixie_jsse_plaintext() so the collector's uprobe can decode it. */
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
extern void pixie_jsse_plaintext(uint64_t, uint32_t, const char*, uint32_t);

static int wv(uint8_t*b,int64_t v){uint64_t u=((uint64_t)v<<1)^(v>>63);int i=0;do{uint8_t x=u&0x7f;u>>=7;if(u)x|=0x80;b[i++]=x;}while(u);return i;}
static int wuv(uint8_t*b,uint32_t v){int i=0;do{uint8_t x=v&0x7f;v>>=7;if(v)x|=0x80;b[i++]=x;}while(v);return i;}
static void p16(uint8_t*b,int v){b[0]=v>>8;b[1]=v;} static void p32(uint8_t*b,uint32_t v){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;} static void p64(uint8_t*b,uint64_t v){for(int i=0;i<8;i++)b[i]=v>>(56-8*i);}
static int build_produce(uint8_t*f){
  int o=0; p16(f+o,0);o+=2;p16(f+o,9);o+=2;p32(f+o,7);o+=4; p16(f+o,1);o+=2;f[o++]='c'; o+=wuv(f+o,0);
  o+=wuv(f+o,0); p16(f+o,-1);o+=2; p32(f+o,30000);o+=4; o+=wuv(f+o,2);
  const char*tp="orders"; o+=wuv(f+o,strlen(tp)+1);memcpy(f+o,tp,strlen(tp));o+=strlen(tp); o+=wuv(f+o,2);
  p32(f+o,3);o+=4;
  uint8_t rb[256]; int rl=0; rb[rl++]=0;rl+=wv(rb+rl,0);rl+=wv(rb+rl,0);rl+=wv(rb+rl,-1);
  const char*val="payload-over-tls"; rl+=wv(rb+rl,strlen(val));memcpy(rb+rl,val,strlen(val));rl+=strlen(val);rl+=wv(rb+rl,0);
  uint8_t batch[512]; int b=0; p64(batch+b,0);b+=8; int blp=b;b+=4; p32(batch+b,0);b+=4; batch[b++]=2;
  p32(batch+b,0);b+=4; p16(batch+b,0);b+=2; p32(batch+b,0);b+=4; p64(batch+b,0);b+=8;p64(batch+b,0);b+=8;
  p64(batch+b,-1);b+=8;p16(batch+b,-1);b+=2;p32(batch+b,-1);b+=4; p32(batch+b,1);b+=4;
  int hl=wv(batch+b,rl); memcpy(batch+b+hl,rb,rl); b+=hl+rl; p32(batch+blp,b-(blp+4));
  o+=wuv(f+o,b+1); memcpy(f+o,batch,b);o+=b; o+=wuv(f+o,0);o+=wuv(f+o,0);
  return o;
}
int main(void){
  uint8_t body[4096]; int n=build_produce(body);
  uint8_t frame[4100]; p32(frame,(uint32_t)n); memcpy(frame+4,body,n); int total=n+4;
  fprintf(stderr,"driver pid=%d emitting %d-byte frame x20\n",(int)getpid(),total);
  for(int i=0;i<20;i++){ pixie_jsse_plaintext(5,0,(const char*)frame,(uint32_t)total); usleep(150000); }
  return 0;
}
