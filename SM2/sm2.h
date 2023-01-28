#ifndef __SM2_HEADER_2015_12_28__
#define __SM2_HEADER_2015_12_28__
 
#include "sm3.h"
#include "miracl.h"
#include "stdint.h"
 
struct text{	unsigned char *content;
				uint16_t len;};
typedef struct text TEXT;
void PrintBuf(unsigned char *buf, int buflen);
void Printch(unsigned char *buf, int buflen);
void PrintBig(big data);
void sm2_keygen(unsigned char *wx, int *wxlen, unsigned char *wy, int *wylen, unsigned char *privkey, int *privkeylen);
int kdf(unsigned char *zl, unsigned char *zr, int klen, unsigned char *kbuf);
int sm2_encrypt(unsigned char *msg,int msglen, unsigned char *wx,int wxlen, \
	              unsigned char *wy,int wylen, unsigned char *outmsg);
int sm2_decrypt(unsigned char *msg,int msglen, unsigned char *privkey, \
	              int privkeylen, unsigned char *outmsg);
int sm2_encrypt_test(TEXT *tx);
int sm2_encrypt_test_nosign(TEXT *tx);
int sm2_sign(unsigned char *msg,int msglen,unsigned char *id,unsigned char *wx,unsigned char *wy,\
            unsigned char *dB,unsigned char *msgsigned);
int sm2_vrisign(unsigned char *msg,int msglen,unsigned char *id,unsigned char *wx,unsigned char *wy,\
            unsigned char *r,unsigned char *s);
#endif
