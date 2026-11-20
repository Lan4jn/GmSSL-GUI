/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 GmSSL Web Toolbox contributors.
 * Original bounded adapters to GmSSL public APIs, not copied implementation.
 * GmSSL upstream is Copyright The GmSSL Project, Apache License 2.0.
 */
#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "extensions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gmssl/digest.h>
#include <gmssl/sha3.h>
#include <gmssl/hmac.h>
#include <gmssl/hkdf.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/aes.h>
#include <gmssl/sm2.h>
#include <gmssl/secp256r1.h>
#include <gmssl/secp384r1.h>
#include <gmssl/zuc.h>
#include <gmssl/sm9.h>
#include <gmssl/sm9_z256.h>
#include <gmssl/mem.h>

#define INPUT_MAX ((size_t)16 * 1024 * 1024)
#define OUTPUT_MAX (INPUT_MAX + 32)
#define ARG_MAX_BYTES 8192
#define KDF_MAX 4096

typedef struct { const char *name; char *value; } OPTION;
typedef struct { OPTION opt[20]; size_t count; } OPTIONS;
static const char *get(const OPTIONS *o, const char *name) {
 size_t i; for (i=0;i<o->count;i++) if (!strcmp(o->opt[i].name,name)) return o->opt[i].value;
 return NULL;
}
static int parse(OPTIONS *o, int argc, char **argv, const char *allowed) {
 int i; memset(o,0,sizeof(*o));
 if (argc>42) return 0;
 for(i=2;i<argc;i++) {
  char marker[40]; const char *flag=argv[i]; char *v;
  if (strlen(flag)>30 || flag[0]!='-' || get(o,flag) || o->count>=20) return 0;
  snprintf(marker,sizeof(marker),"|%s|",flag);
  if (!strstr(allowed,marker)) return 0;
  if (!strcmp(flag,"-bin")) v="1";
  else { if (++i>=argc || strlen(argv[i])>ARG_MAX_BYTES) return 0; v=argv[i]; }
  o->opt[o->count++]=(OPTION){flag,v};
 }
 return 1;
}
static int number(const char *s,size_t min,size_t max,size_t fallback,size_t *v) {
 char *end; unsigned long long x;
 if (!s) { *v=fallback; return 1; }
 if (!*s || *s<'0' || *s>'9') return 0;
 errno=0; x=strtoull(s,&end,10);
 if (errno || *end || x<min || x>max) return 0;
 *v=(size_t)x; return 1;
}
static int nibble(char c) {
 if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
 if(c>='A'&&c<='F')return c-'A'+10; return -1;
}
static int hex(const char *s,uint8_t *out,size_t cap,size_t *len) {
 size_t n,i; *len=0; if(!s)return 0; n=strlen(s);
 if(n%2 || n/2>cap)return 0;
 for(i=0;i<n/2;i++){int a=nibble(s[2*i]),b=nibble(s[2*i+1]); if(a<0||b<0)return 0;out[i]=(uint8_t)((a<<4)|b);}
 *len=n/2;return 1;
}
static int optional_hex(const char *s,uint8_t *out,size_t cap,size_t *len) {
 if(!s){*len=0;return 1;}return hex(s,out,cap,len);
}
/* Only direct children of the worker cwd input/output directories are admitted.
 * Parent directories must be real directories, not symlink aliases. */
static int isolated_path(const char *path,const char *dir) {
 char cwd[PATH_MAX],parent[PATH_MAX],resolved[PATH_MAX],expected[PATH_MAX];
 const char *base,*slash;size_t pn,i;struct stat st;
 if(!path||strlen(path)>=sizeof(parent)||!(slash=strrchr(path,'/')))return 0;
 base=slash+1;pn=(size_t)(slash-path);if(!pn||!*base||strlen(base)>128)return 0;
 for(i=0;base[i];i++)if(!((base[i]>='a'&&base[i]<='z')||(base[i]>='A'&&base[i]<='Z')||(base[i]>='0'&&base[i]<='9')||base[i]=='_'||base[i]=='-'||base[i]=='.'))return 0;
 if(base[0]=='.'||!getcwd(cwd,sizeof(cwd)))return 0;
 memcpy(parent,path,pn);parent[pn]=0;
 if(snprintf(expected,sizeof(expected),"%s/%s",cwd,dir)>=(int)sizeof(expected))return 0;
 if(lstat(expected,&st)||!S_ISDIR(st.st_mode)||!realpath(parent,resolved)||strcmp(resolved,expected))return 0;
 return 1;
}
static FILE *open_input_file(const char *path) {
 int fd; struct stat st; FILE *f;
 if(!path||!isolated_path(path,"input"))return NULL;
 fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return NULL;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||(uint64_t)st.st_size>INPUT_MAX){close(fd);return NULL;}
 f=fdopen(fd,"rb");if(!f){close(fd);return NULL;}
 return f;
}
static int read_input(const char *path,uint8_t *buf,size_t *len) {
 FILE *f=stdin; size_t n; *len=0;
 if(path){f=open_input_file(path);if(!f)return 0;}
 while(*len<INPUT_MAX){n=fread(buf+*len,1,INPUT_MAX-*len,f);*len+=n;if(!n)break;}
 if(ferror(f)||fgetc(f)!=EOF){if(path)fclose(f);return 0;}
 if(path&&fclose(f))return 0;return 1;
}
static int write_output_file(const char *path,const uint8_t *buf,size_t n,int bin) {
 int fd,ok=1; FILE *f; size_t i;
 if(!path||!isolated_path(path,"output")||n>OUTPUT_MAX)return 0;
 fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return 0;
 f=fdopen(fd,"wb");if(!f){close(fd);return 0;}
 if(bin){if(fwrite(buf,1,n,f)!=n)ok=0;}
 else {for(i=0;i<n;i++)if(fprintf(f,"%02x",buf[i])<0){ok=0;break;}if(fputc('\n',f)==EOF)ok=0;}
 if(fflush(f))ok=0;if(fclose(f))ok=0;return ok;
}
static int output(const OPTIONS *o,const uint8_t *buf,size_t n,int force_binary) {
 const char *path=get(o,"-out");int bin=force_binary||get(o,"-bin")!=NULL;
 if(path)return write_output_file(path,buf,n,bin);
 if(n>OUTPUT_MAX)return 0;
 if(bin){if(fwrite(buf,1,n,stdout)!=n)return 0;}
 else {size_t i;for(i=0;i<n;i++)if(fprintf(stdout,"%02x",buf[i])<0)return 0;if(fputc('\n',stdout)==EOF)return 0;}
 return fflush(stdout)==0;
}
static const DIGEST *md(const char *name) {
 if(!name)return NULL;
 return digest_from_name(name);
}
static int digest_run(const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 const char *alg=get(o,"-alg");const DIGEST *d;size_t L;
 if(!alg)return 0;
 if(!strcmp(alg,"shake128")||!strcmp(alg,"shake256")) {
  if(!get(o,"-outlen")||!number(get(o,"-outlen"),1,KDF_MAX,0,&L))return 0;
  if(!strcmp(alg,"shake128"))shake128(in,n,out,L);else shake256(in,n,out,L);*len=L;return 1;
 }
 if(get(o,"-outlen"))return 0;
 if(!strcmp(alg,"sha3-256")){sha3_256(in,n,out);*len=32;return 1;}
 if(!strcmp(alg,"sha3-512")){sha3_512(in,n,out);*len=64;return 1;}
 d=md(alg);return d&&digest(d,in,n,out,len)==1;
}
static int kdf_run(const char *cmd,const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 uint8_t key[4096]={0},salt[64]={0},info[4096]={0},prk[64]={0};
 size_t kn=0,sn=0,info_n=0,pn=0,iter=0,L=0;const DIGEST *d=NULL;int ok=0;
 if(!strcmp(cmd,"api_sm3_kdf")) {
  SM3_KDF_CTX ctx;
  if(!get(o,"-outlen")||!number(get(o,"-outlen"),1,KDF_MAX,0,&L))goto end;
  sm3_kdf_init(&ctx,L);sm3_kdf_update(&ctx,in,n);sm3_kdf_finish(&ctx,out);gmssl_secure_clear(&ctx,sizeof(ctx));ok=1;goto end;
 }
 if(!(d=md(get(o,"-alg"))))goto end;
 if(!strcmp(cmd,"api_hmac")) {
  if(!hex(get(o,"-key"),key,sizeof(key),&kn))goto end;
  ok=hmac(d,key,kn,in,n,out,len)==1;goto end;
 }
 if(!get(o,"-outlen")||!number(get(o,"-outlen"),1,KDF_MAX,0,&L)||!optional_hex(get(o,"-salt"),salt,sizeof(salt),&sn))goto end;
 if(!strcmp(cmd,"api_hkdf")) {
  if(L>255*d->digest_size||!optional_hex(get(o,"-info"),info,sizeof(info),&info_n))goto end;
  if(hkdf_extract(d,salt,sn,in,n,prk,&pn)!=1)goto end;
  ok=hkdf_expand(d,prk,pn,info,info_n,L,out)==1;
 } else {
  const char *pass=get(o,"-pass");
  if(!pass||strlen(pass)>4096||!get(o,"-salt")||!get(o,"-iter")||!number(get(o,"-iter"),1,1000000,0,&iter))goto end;
  /* Bound aggregate HMAC work as well as either individual parameter. */
  if(((L+d->digest_size-1)/d->digest_size)*iter>4000000)goto end;
  ok=pbkdf2_hmac_genkey(d,pass,strlen(pass),salt,sn,iter,L,out)==1;
 }
end:
 if(ok&&strcmp(cmd,"api_hmac"))*len=L;
 gmssl_secure_clear(key,sizeof(key));gmssl_secure_clear(salt,sizeof(salt));gmssl_secure_clear(info,sizeof(info));gmssl_secure_clear(prk,sizeof(prk));return ok;
}
static int aes_run(const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 AES_KEY ctx;uint8_t key[32]={0},iv[32]={0},aad[4096]={0};size_t kn=0,vn=0,an=0,t=16,i;int ok=0,decrypting,auth;
 const char *mode=get(o,"-mode"),*op=get(o,"-op"),*padding=get(o,"-padding");
 memset(&ctx,0,sizeof(ctx));
 if(!mode||!op||(strcmp(op,"encrypt")&&strcmp(op,"decrypt")))goto end;
 decrypting=!strcmp(op,"decrypt");auth=!strcmp(mode,"gcm")||!strcmp(mode,"ccm");
 if(!hex(get(o,"-key"),key,sizeof(key),&kn)||(kn!=16&&kn!=24&&kn!=32))goto end;
 if(!optional_hex(get(o,"-iv"),iv,sizeof(iv),&vn)||!optional_hex(get(o,"-aad"),aad,sizeof(aad),&an))goto end;
 if(padding&&strcmp(mode,"cbc"))goto end;
 if(!auth&&(get(o,"-aad")||get(o,"-taglen")))goto end;
 if(!strcmp(mode,"ecb")){if(get(o,"-iv")||n%16)goto end;}
 else if(!strcmp(mode,"cbc")||!strcmp(mode,"ctr")){if(vn!=16)goto end;}
 else if(!strcmp(mode,"gcm")){if(vn<1||vn>32)goto end;}
 else if(!strcmp(mode,"ccm")){if(vn<7||vn>13)goto end;}
 else goto end;
 if(!padding)padding="none";
 if(strcmp(padding,"none")&&strcmp(padding,"pkcs7"))goto end;
 if(!strcmp(mode,"cbc")&&!strcmp(padding,"none")&&n%16)goto end;
 if(auth){
  if(!number(get(o,"-taglen"),4,16,16,&t))goto end;
  if(!strcmp(mode,"gcm")&&t!=4&&t!=8&&t<12)goto end;
  if(!strcmp(mode,"ccm")&&t%2)goto end;
  if(decrypting){if(n<t)goto end;n-=t;}
  if(!strcmp(mode,"ccm")&&vn==13&&n>=65536)goto end;
 }
 if((decrypting&&(!strcmp(mode,"cbc")||!strcmp(mode,"ecb"))?aes_set_decrypt_key(&ctx,key,kn):aes_set_encrypt_key(&ctx,key,kn))!=1)goto end;
 *len=n;
 if(!strcmp(mode,"ecb")){for(i=0;i<n;i+=16){if(decrypting)aes_decrypt(&ctx,in+i,out+i);else aes_encrypt(&ctx,in+i,out+i);}ok=1;}
 else if(!strcmp(mode,"ctr")){
  uint8_t check[16];size_t carry=n?(n-1)/16:0;memcpy(check,iv,16);
  for(i=16;i>0;i--){carry+=check[i-1];check[i-1]=(uint8_t)carry;carry>>=8;}if(carry)goto end;
  aes_ctr_encrypt(&ctx,iv,in,n,out);gmssl_secure_clear(check,sizeof(check));ok=1;
 }
 else if(!strcmp(mode,"cbc")){
  if(!strcmp(padding,"pkcs7"))ok=(decrypting?aes_cbc_padding_decrypt(&ctx,iv,in,n,out,len):aes_cbc_padding_encrypt(&ctx,iv,in,n,out,len))==1;
  else {if(decrypting)aes_cbc_decrypt_blocks(&ctx,iv,in,n/16,out);else aes_cbc_encrypt_blocks(&ctx,iv,in,n/16,out);ok=1;}
 }
 else if(!strcmp(mode,"gcm")){
  if(decrypting)ok=aes_gcm_decrypt(&ctx,iv,vn,aad,an,in,n,in+n,t,out)==1;
  else {ok=aes_gcm_encrypt(&ctx,iv,vn,aad,an,in,n,out,t,out+n)==1;*len=n+t;}
 }
 else {
  if(decrypting)ok=aes_ccm_decrypt(&ctx,iv,vn,aad,an,in,n,in+n,t,out)==1;
  else {ok=aes_ccm_encrypt(&ctx,iv,vn,aad,an,in,n,out,t,out+n)==1;*len=n+t;}
 }
end:
 gmssl_secure_clear(&ctx,sizeof(ctx));gmssl_secure_clear(key,sizeof(key));gmssl_secure_clear(iv,sizeof(iv));gmssl_secure_clear(aad,sizeof(aad));return ok;
}
static int ec_run(const char *cmd,const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 const char *curve=get(o,"-curve");const DIGEST *d=NULL;
 uint8_t raw[48]={0},pub[97]={0},sig[104]={0},dgst[64]={0};size_t rn=0,pn=0,sn=0,dn=0;int ok=0;
 SECP256R1_KEY k256;SECP384R1_KEY k384;SM2_KEY ks;secp256r1_t s256;secp384r1_t s384;sm2_z256_t ss;
 memset(&k256,0,sizeof(k256));memset(&k384,0,sizeof(k384));memset(&ks,0,sizeof(ks));
 memset(s256,0,sizeof(s256));memset(s384,0,sizeof(s384));memset(ss,0,sizeof(ss));
 if(!strcmp(cmd,"api_sm2_ecdh"))curve="sm2";
 if(!curve)goto end;
 if(strcmp(cmd,"api_ec_verify")){
  if(!hex(get(o,"-key"),raw,sizeof(raw),&rn))goto end;
 }else if(!hex(get(o,"-sig"),sig,sizeof(sig),&sn)||sn<8)goto end;
 if(!strcmp(cmd,"api_ec_sign")||!strcmp(cmd,"api_ec_verify")){
  const char *alg=get(o,"-alg");
  if(!alg||(strcmp(alg,"sha256")&&strcmp(alg,"sha384"))||!(d=md(alg))||digest(d,in,n,dgst,&dn)!=1)goto end;
 }
 if(!strcmp(cmd,"api_ecdh")||!strcmp(cmd,"api_sm2_ecdh")||!strcmp(cmd,"api_ec_verify")){
  if(!hex(get(o,"-pub"),pub,sizeof(pub),&pn))goto end;
 }
 if(!strcmp(curve,"P256")){
  if(strcmp(cmd,"api_ec_verify")){
   if(rn!=32||secp256r1_from_32bytes(s256,raw)!=1||secp256r1_key_set_private_key(&k256,s256)!=1)goto end;
  }
  if(!strcmp(cmd,"api_ec_public")){ok=secp256r1_point_to_uncompressed_octets(&k256.public_key,out)==1;*len=65;}
  else if(!strcmp(cmd,"api_ec_sign"))ok=secp256r1_ecdsa_sign(&k256,dgst,dn,out,len)==1;
  else {
   if(pn!=65||secp256r1_point_from_uncompressed_octets(&k256.public_key,pub)!=1||secp256r1_point_is_at_infinity(&k256.public_key))goto end;
   if(!strcmp(cmd,"api_ec_verify")){ok=secp256r1_ecdsa_verify(&k256,dgst,dn,sig,sn)==1;*len=0;}
   else {ok=secp256r1_ecdh(&k256,pub,out)==1;*len=32;}
  }
 }else if(!strcmp(curve,"P384")){
  if(strcmp(cmd,"api_ec_verify")){
   if(rn!=48||secp384r1_from_48bytes(s384,raw)!=1||secp384r1_key_set_private_key(&k384,s384)!=1)goto end;
  }
  if(!strcmp(cmd,"api_ec_public")){ok=secp384r1_point_to_uncompressed_octets(&k384.public_key,out)==1;*len=97;}
  else if(!strcmp(cmd,"api_ec_sign"))ok=secp384r1_ecdsa_sign(&k384,dgst,dn,out,len)==1;
  else {
   if(pn!=97||secp384r1_point_from_uncompressed_octets(&k384.public_key,pub)!=1||secp384r1_point_is_at_infinity(&k384.public_key))goto end;
   if(!strcmp(cmd,"api_ec_verify")){ok=secp384r1_ecdsa_verify(&k384,dgst,dn,sig,sn)==1;*len=0;}
   else {ok=secp384r1_ecdh(&k384,pub,out)==1;*len=48;}
  }
 }else if(!strcmp(curve,"sm2")&&(!strcmp(cmd,"api_ec_public")||!strcmp(cmd,"api_sm2_ecdh"))){
  if(rn!=32)goto end;sm2_z256_from_bytes(ss,raw);if(sm2_key_set_private_key(&ks,ss)!=1)goto end;
  if(!strcmp(cmd,"api_ec_public")){out[0]=4;ok=sm2_z256_point_to_bytes(&ks.public_key,out+1)==1;*len=65;}
  else {SM2_Z256_POINT peer;
   if(pn!=65||pub[0]!=4||sm2_z256_point_from_bytes(&peer,pub+1)!=1||sm2_z256_point_is_at_infinity(&peer))goto end;
   ok=sm2_ecdh(&ks,pub,out)==1;*len=32;gmssl_secure_clear(&peer,sizeof(peer));}
 }
end:
 gmssl_secure_clear(raw,sizeof(raw));gmssl_secure_clear(pub,sizeof(pub));gmssl_secure_clear(sig,sizeof(sig));gmssl_secure_clear(dgst,sizeof(dgst));
 gmssl_secure_clear(&k256,sizeof(k256));gmssl_secure_clear(&k384,sizeof(k384));gmssl_secure_clear(&ks,sizeof(ks));
 gmssl_secure_clear(s256,sizeof(s256));gmssl_secure_clear(s384,sizeof(s384));gmssl_secure_clear(ss,sizeof(ss));return ok;
}
static int zuc_mac_run(const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 ZUC_MAC_CTX ctx; uint8_t key[16]={0},iv[16]={0}; size_t kn=0,vn=0,nbits=0; int ok=0;
 memset(&ctx,0,sizeof(ctx));
 if(!hex(get(o,"-key"),key,sizeof(key),&kn)||kn!=16)goto end;
 if(!hex(get(o,"-iv"),iv,sizeof(iv),&vn)||vn!=16)goto end;
 if(get(o,"-nbits")){
  if(!number(get(o,"-nbits"),0,n*8,n*8,&nbits))goto end;
  if(n==0){if(nbits!=0)goto end;}
  else {
   size_t rem;
   if(nbits==0||(nbits+7)/8!=n)goto end;
   rem=nbits%8;
   if(rem){uint8_t mask=(uint8_t)((1<<(8-rem))-1);if(in[n-1]&mask)goto end;}
  }
 }else nbits=n*8;
 zuc_mac_init(&ctx,key,iv);
 zuc_mac_finish(&ctx,in,nbits,out);
 *len=4;ok=1;
end:
 gmssl_secure_clear(&ctx,sizeof(ctx));gmssl_secure_clear(key,sizeof(key));gmssl_secure_clear(iv,sizeof(iv));
 return ok;
}
static int zuc256_mac_run(const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 ZUC256_MAC_CTX ctx; uint8_t key[32]={0},iv[23]={0}; size_t kn=0,vn=0,nbits=0; int ok=0,macbits=32;
 const char *mb_str=get(o,"-macbits");
 memset(&ctx,0,sizeof(ctx));
 if(!hex(get(o,"-key"),key,sizeof(key),&kn)||kn!=32)goto end;
 if(!hex(get(o,"-iv"),iv,sizeof(iv),&vn)||vn!=23)goto end;
 if(mb_str){
  if(!strcmp(mb_str,"32"))macbits=32;
  else if(!strcmp(mb_str,"64"))macbits=64;
  else if(!strcmp(mb_str,"128"))macbits=128;
  else goto end;
 }
 if(get(o,"-nbits")){
  if(!number(get(o,"-nbits"),0,n*8,n*8,&nbits))goto end;
  if(n==0){if(nbits!=0)goto end;}
  else {
   size_t rem;
   if(nbits==0||(nbits+7)/8!=n)goto end;
   rem=nbits%8;
   if(rem){uint8_t mask=(uint8_t)((1<<(8-rem))-1);if(in[n-1]&mask)goto end;}
  }
 }else nbits=n*8;
 zuc256_mac_init(&ctx,key,iv,macbits);
 zuc256_mac_finish(&ctx,in,nbits,out);
 *len=(size_t)(macbits/8);ok=1;
end:
 gmssl_secure_clear(&ctx,sizeof(ctx));gmssl_secure_clear(key,sizeof(key));gmssl_secure_clear(iv,sizeof(iv));
 return ok;
}
static int sm9_kem_run(const OPTIONS *o,const uint8_t *in,size_t n,uint8_t *out,size_t *len) {
 const char *op=get(o,"-op"),*id=get(o,"-id");
 SM9_ENC_MASTER_KEY mpk; SM9_ENC_KEY key; SM9_Z256_POINT C;
 uint8_t cbuf[65]={0}; size_t klen=0,idlen=0; int ok=0; FILE *f=NULL;
 memset(&mpk,0,sizeof(mpk));memset(&key,0,sizeof(key));memset(&C,0,sizeof(C));
 if(!op||!id||!(idlen=strlen(id))||idlen>8191)goto end;
 if(!get(o,"-outlen")||!number(get(o,"-outlen"),1,KDF_MAX,0,&klen))goto end;
 if(!strcmp(op,"encrypt")){
  if(get(o,"-key")||get(o,"-pass")||get(o,"-in")||!get(o,"-pubmaster")||!get(o,"-cipherout"))goto end;
  f=open_input_file(get(o,"-pubmaster"));if(!f)goto end;
  if(sm9_enc_master_public_key_from_pem(&mpk,f)!=1){fclose(f);goto end;}
  fclose(f);f=NULL;
  if(sm9_kem_encrypt(&mpk,id,idlen,klen,out,&C)!=1)goto end;
  if(sm9_z256_point_to_uncompressed_octets(&C,cbuf)!=1)goto end;
  if(!write_output_file(get(o,"-cipherout"),cbuf,65,get(o,"-bin")!=NULL))goto end;
  *len=klen;ok=1;
 }else if(!strcmp(op,"decrypt")){
  const char *pass=get(o,"-pass");
  if(get(o,"-pubmaster")||get(o,"-cipherout")||!get(o,"-key")||!pass)goto end;
  if(n==65&&in[0]==0x04)memcpy(cbuf,in,65);
  else {
   size_t hex_len=n;
   while(hex_len>0&&(in[hex_len-1]=='\n'||in[hex_len-1]=='\r'))hex_len--;
   if(hex_len==130){
    char hex_str[131]; size_t parsed=0;
    memcpy(hex_str,in,130);hex_str[130]=0;
    if(!hex(hex_str,cbuf,sizeof(cbuf),&parsed)||parsed!=65||cbuf[0]!=0x04)goto end;
   }else goto end;
  }
  if(sm9_z256_point_from_uncompressed_octets(&C,cbuf)!=1||sm9_z256_point_is_at_infinity(&C)||sm9_z256_point_is_on_curve(&C)!=1)goto end;
  f=open_input_file(get(o,"-key"));if(!f)goto end;
  if(sm9_enc_key_info_decrypt_from_pem(&key,pass,f)!=1){fclose(f);goto end;}
  fclose(f);f=NULL;
  if(sm9_kem_decrypt(&key,id,idlen,&C,klen,out)!=1)goto end;
  *len=klen;ok=1;
 }
end:
 if(f)fclose(f);
 gmssl_secure_clear(&mpk,sizeof(mpk));gmssl_secure_clear(&key,sizeof(key));
 gmssl_secure_clear(&C,sizeof(C));gmssl_secure_clear(cbuf,sizeof(cbuf));
 return ok;
}
int gmssl_extension_main(int argc,char **argv) {
 OPTIONS o;const char *cmd,*allowed;uint8_t *in=NULL,*out=NULL;size_t n=0,on=0,i;int ok=0,needs_input=1,aes=0;
 signal(SIGPIPE,SIG_IGN);
 if(argc<2)return -2;cmd=argv[1];
 if(!strcmp(cmd,"api_digest"))allowed="|-alg||-outlen||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_hmac"))allowed="|-alg||-key||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_hkdf"))allowed="|-alg||-salt||-info||-outlen||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_pbkdf2")){allowed="|-alg||-pass||-salt||-iter||-outlen||-out||-bin|";needs_input=0;}
 else if(!strcmp(cmd,"api_sm3_kdf"))allowed="|-outlen||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_aes")){allowed="|-mode||-op||-key||-iv||-aad||-taglen||-padding||-in||-out|";aes=1;}
 else if(!strcmp(cmd,"api_ec_public")){allowed="|-curve||-key||-out||-bin|";needs_input=0;}
 else if(!strcmp(cmd,"api_ec_sign"))allowed="|-curve||-key||-alg||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_ec_verify"))allowed="|-curve||-pub||-alg||-sig||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_ecdh")){allowed="|-curve||-key||-pub||-out||-bin|";needs_input=0;}
 else if(!strcmp(cmd,"api_sm2_ecdh")){allowed="|-key||-pub||-out||-bin|";needs_input=0;}
 else if(!strcmp(cmd,"api_zuc_mac"))allowed="|-key||-iv||-nbits||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_zuc256_mac"))allowed="|-key||-iv||-macbits||-nbits||-in||-out||-bin|";
 else if(!strcmp(cmd,"api_sm9_kem"))allowed="|-op||-pubmaster||-key||-pass||-id||-outlen||-cipherout||-in||-out||-bin|";
 else return -2;
 if(!parse(&o,argc,argv,allowed))goto end;
 if(!strcmp(cmd,"api_sm9_kem")){
  const char *op=get(&o,"-op");
  if(op&&!strcmp(op,"encrypt"))needs_input=0;
 }
 in=malloc(INPUT_MAX+1);out=malloc(OUTPUT_MAX);if(!in||!out)goto end;
 if(needs_input&&!read_input(get(&o,"-in"),in,&n))goto end;
 if(!strcmp(cmd,"api_digest"))ok=digest_run(&o,in,n,out,&on);
 else if(aes)ok=aes_run(&o,in,n,out,&on);
 else if(!strncmp(cmd,"api_ec",6)||!strcmp(cmd,"api_sm2_ecdh"))ok=ec_run(cmd,&o,in,n,out,&on);
 else if(!strcmp(cmd,"api_zuc_mac"))ok=zuc_mac_run(&o,in,n,out,&on);
 else if(!strcmp(cmd,"api_zuc256_mac"))ok=zuc256_mac_run(&o,in,n,out,&on);
 else if(!strcmp(cmd,"api_sm9_kem"))ok=sm9_kem_run(&o,in,n,out,&on);
 else ok=kdf_run(cmd,&o,in,n,out,&on);
 /* Authenticated decrypt output remains private until the complete tag validates. */
 if(ok)ok=output(&o,out,on,aes);
end:
 if(in){gmssl_secure_clear(in,INPUT_MAX+1);free(in);}if(out){gmssl_secure_clear(out,OUTPUT_MAX);free(out);}
 for(i=0;i<o.count;i++)if(!strcmp(o.opt[i].name,"-key")||!strcmp(o.opt[i].name,"-pass"))gmssl_secure_clear(o.opt[i].value,strlen(o.opt[i].value));
 if(!ok)fprintf(stderr,"extension: invalid parameters, input, or cryptographic verification failed\n");
 return ok?0:1;
}
