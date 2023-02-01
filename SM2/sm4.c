#include "sm4.h"
#include "sm2.h"
#include "miracl.h"
#include "stm32f10x.h"
#include "string.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif
#define SEED_CONST 0x1BD8C95A
/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n%32) 
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n%32)))

#define SWAP(a,b) { unsigned long t = a; a = b; b = t; t = 0; }
/*
 * Expanded SM4 S-boxes
 * Sbox table: 8bits input convert to 8 bits output*/
 
static const unsigned char SboxTable[16][16] = 
{
{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
{0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
{0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
{0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
{0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
{0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
{0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
{0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
{0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
{0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
{0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
{0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
{0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
{0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
{0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
{0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

/* System parameter */
static const unsigned long FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};

/* fixed parameter */
static const unsigned long CK[32] =
{
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};



/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}

/*
 * private F(Lt) function:
 * "T algorithm" == "L algorithm" + "t algorithm".
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: c: c is calculated with line algorithm "L" and nonline algorithm "t"
 */
static unsigned long sm4Lt(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long c = 0;
    unsigned char a[4];
	unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    c =bb^(ROTL(bb, 2))^(ROTL(bb, 10))^(ROTL(bb, 18))^(ROTL(bb, 24));
    return c;
}

/*
 * private F function:
 * Calculating and getting encryption/decryption contents.
 * args:    [in] x0: original contents;
 * args:    [in] x1: original contents;
 * args:    [in] x2: original contents;
 * args:    [in] x3: original contents;
 * args:    [in] rk: encryption/decryption key;
 * return the contents of encryption/decryption contents.
 */
static unsigned long sm4F(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, unsigned long rk)
{
    return (x0^sm4Lt(x1^x2^x3^rk));
}
/** 
	* @brief 由随机数生成加密密钥
	*@param key[]:返回字符型的加密密钥
*/
int gen_key(unsigned char* key)
{
	big k;
	miracl instance;
	miracl *mip = &instance;
   	mip = mirsys(mip, 20, 0);   /* Use Hex Internally */
	mip->IOBASE = 16;

	char mem[MR_BIG_RESERVE(1)];
	memset(mem, 0, MR_BIG_RESERVE(1));
	k = mirvar_mem(mip, mem, 0);
	
	irand(mip, SEED_CONST+TIM_GetCounter(TIM3));
	bigbits(mip,128, k);
	big_to_bytes(mip, 16, k, (char *)key, TRUE);

	memset(mem,0,MR_ECP_RESERVE(1));
	mirexit(mip);
	return 0;
}

/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
static unsigned long sm4CalciRK(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}
/*  @brief: 由加密密钥得到轮密钥
    args: sk[]:轮密钥
         key[]:字符型的加密密钥
*/
static void sm4_setkey( unsigned long SK[32], unsigned char key[16] )
{
    unsigned long MK[4];//加密密钥
    unsigned long k[36];
    unsigned long i = 0;

    GET_ULONG_BE( MK[0], key, 0 );//将字符型密钥转换为long放入MK中
    GET_ULONG_BE( MK[1], key, 4 );
    GET_ULONG_BE( MK[2], key, 8 );
    GET_ULONG_BE( MK[3], key, 12 );
    k[0] = MK[0]^FK[0];
    k[1] = MK[1]^FK[1];
    k[2] = MK[2]^FK[2];
    k[3] = MK[3]^FK[3];
    for(; i<32; i++)
    {
        k[i+4] = k[i] ^ (sm4CalciRK(k[i+1]^k[i+2]^k[i+3]^CK[i]));
        SK[i] = k[i+4];//轮密钥
	}

}

/*
 * SM4 standard one round processing
 *
 */
static void sm4_one_round( unsigned long sk[32],
                    unsigned char input[16],
                    unsigned char output[16] )
{
	unsigned long ulbuf[36];
    unsigned int i = 0;

    memset(ulbuf, 0, sizeof(ulbuf));
    GET_ULONG_BE( ulbuf[0], input, 0 )
    GET_ULONG_BE( ulbuf[1], input, 4 )
    GET_ULONG_BE( ulbuf[2], input, 8 )
    GET_ULONG_BE( ulbuf[3], input, 12 )
    while(i<32)
    {
       ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], sk[i]);
// #ifdef _DEBUG
//        	printf("rk(%02d) = 0x%08x,  X(%02d) = 0x%08x \n",i,sk[i], i, ulbuf[i+4] );
// #endif
	    i++;
    }
	PUT_ULONG_BE(ulbuf[35],output,0);
	PUT_ULONG_BE(ulbuf[34],output,4);
	PUT_ULONG_BE(ulbuf[33],output,8);
	PUT_ULONG_BE(ulbuf[32],output,12);
	
}

/*
 * SM4 key schedule (128-bit, encryption)
 */
void sm4_setkey_enc( sm4_context *ctx,  unsigned char key[16] )
{
    ctx->mode = SM4_ENCRYPT;
	sm4_setkey( ctx->sk, key );
}

/*
 * SM4 key schedule (128-bit, decryption)
 */
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] )
{
	int i;
	ctx->mode = SM4_DECRYPT;
	sm4_setkey( ctx->sk, key );
	for( i = 0; i < 16; i++ )
	{
			SWAP( ctx->sk[ i ], ctx->sk[ 31-i] );
	}
}


/*
 * SM4-ECB block encryption/decryption
 */

void sm4_crypt_ecb_old( sm4_context *ctx,
				   int mode,
				   int length,
				   unsigned char *input,
           unsigned char *output)
{
    while( length > 0 )
    {
        sm4_one_round( ctx->sk, input, output );
        input  += 16;
        output += 16;
        length -= 16;
    }

}

/*
 * SM4-CBC buffer encryption/decryption
 */
void sm4_crypt_cbc_old( sm4_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];//暂时存储此次加密后的密文，作为下一个iv

    if( mode == SM4_ENCRYPT )
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
            input[i] = (unsigned char)( input[i] ^ iv[i] );

            sm4_one_round( ctx->sk, input, output );
			memcpy( iv, output, 16 );//当加密端和解密端不在同一应用是应去掉注释
            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else /* SM4_DECRYPT */
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            sm4_one_round( ctx->sk, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
}

/**
  * @brief SM4-ECB + PKCS7算法
	* @param ctx:      SM4结构体，主要是包含初始秘钥（对于ECB模式的加密来说，
										 不同之处就在于它的初始化时秘钥的初始方法不同,加密操作
										 都是一样的）
	* @param mode:     加密：SM4_ENCRYPT 解密：SM4_DECRYPT
	* @param length:   需要处理的数据长度指针
	* @param input:    需要处理的数据
	* @param output:   处理完的数据
	* @attention：     1、length参数类型为指针，在此函数内部，该参数会
										 被修改为加解密后数据的实际长度。
										 2、对于input参数，要求其必须富裕出最少16字节的空间以供
										填充数据。
										 3、对于解密的output，并未真正去除掉填充的数据，只是
										对数据长度进行去填充长度操作，请按length长度取值
  * @retval void
  */
void sm4_crypt_ecb( sm4_context *ctx, int mode, unsigned int *length, \
										unsigned char *input, unsigned char *output)
{
	/* 填充长度及填充值 */
	int padding_value;
	if(mode == SM4_ENCRYPT)
	{	
		padding_value = 16 - (*length % 16);
		/* 填充 */
		if(padding_value!=16)
		{
			memset(input + *length, padding_value, padding_value);
			/* 填充后长度 */
			*length += padding_value;
		}
		/* 加密 */
		sm4_crypt_ecb_old(ctx, mode, *length, input, output);
		
	}
	else //SM4_DECRYPT
	{
		sm4_crypt_ecb_old(ctx, mode, *length, input, output);
		
		/* 去掉填充长度 */
		*length -= output[*length - 1];
	}
}


/**
	* @brief          SM4-CBC + PKCS7算法
	* @param ctx      SM4 context
	* @param mode     加密：SM4_ENCRYPT 解密：SM4_DECRYPT
	* @param length   需要处理的数据长度指针
	* @param iv       初始化向量(使用后更新)
	* @param input:   需要处理的数据
	* @param output:  处理完的数据
	* @attention：    1、length参数类型为指针，在此函数内部，该参数会
										被修改为加解密后数据的实际长度。
										2、对于input参数，要求其必须富裕出最少16字节的空间以供
										填充数据。
										3、对于解密的output，并未真正去除掉填充的数据，只是
										对数据长度进行去填充长度操作，请按length长度取值
  * @retval void
 */
void sm4_crypt_cbc( sm4_context *ctx, int mode, unsigned int *length, unsigned char iv[16], \
                    unsigned char *input, unsigned char *output )
{
	/* 填充长度及填充值 */
	int padding_value;
	
	if(mode == SM4_ENCRYPT)
	{
		padding_value = 16 - (*length % 16);
		
		if(padding_value!=16)
		{
			memset(input + *length, padding_value, padding_value);
			/* 填充后长度 */
			*length += padding_value;
		}

		sm4_crypt_cbc_old(ctx, mode, *length, iv, input, output);
	}
	else //SM4_DECRYPT
	{
		sm4_crypt_cbc_old(ctx, mode, *length, iv, input, output);

		*length -= output[*length - 1];
	}
}


int sm4_test_ecb(TEXT *tx,u16 len)
{	
	printf("\r\n***************** SM4_ECB *****************\r\n");
//	unsigned char key[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}; // 密钥 
	unsigned char key[16];
    unsigned char Y[len]; // 密文 
	unsigned char rX[len]; // 解密出的明文
	printf("明文："); 
	PrintBuf(tx->content, len);
	sm4_encrypt_cbc(key,tx->content,Y,len);
	printf("密钥：");
	PrintBuf(key,16);
	printf("密文：");
	PrintBuf(Y,len);
	sm4_decrypt_cbc( key,Y, rX ,len,0);
	printf("解密后明文：");
	PrintBuf(rX,len);
	return 0;
}

int sm4_test_cbc(TEXT *tx,u16 len)
{
    printf("\r\n***************** SM4_CBC *****************\r\n");	
//	unsigned char key[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}; // 密钥 
	unsigned char key[16];
    unsigned char Y[len]; // 密文 
	unsigned char rX[len]; // 解密出的明文 
	printf("明文："); 
	PrintBuf(tx->content, len);
	sm4_encrypt_cbc(key,tx->content,Y,len);
	printf("密钥：");
	PrintBuf(key,16);
	printf("密文：");
	PrintBuf(Y,len);
	sm4_decrypt_cbc( key,Y, rX ,len,0);
	printf("解密后明文：");
	PrintBuf(rX,len);
	return 0;	
}

int sm4_encrypt_ecb(unsigned char *key,unsigned char *txcontent,unsigned char *rxcontent,u16 len)
{	
	printf("\r\n***************** SM4_encrypt_ECB *****************\r\n");
	sm4_context context;
	sm4_context* ctx=&context;
	gen_key(key);//生成主密钥
	sm4_setkey_enc(ctx,key);//计算轮密钥
	sm4_crypt_ecb_old(ctx,ctx->mode,len,txcontent,rxcontent);//加密
	return 0;
}

int sm4_encrypt_cbc(unsigned char *key,unsigned char *txcontent,unsigned char *rxcontent,u16 len)
{	
	printf("\r\n***************** SM4_encrypt_CBC *****************\r\n");
	unsigned char iv[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}; 
	sm4_context context;
	sm4_context* ctx=&context;
	gen_key(key);//生成主密钥
	sm4_setkey_enc(ctx,key);//计算轮密钥
	sm4_crypt_cbc_old( ctx, ctx->mode,len, iv,txcontent, rxcontent );//加密
	return 0;
}

int sm4_decrypt_ecb(unsigned char *key,unsigned char *input,unsigned char *output,u16 len)
{
    printf("\r\n***************** SM4_ECB *****************\r\n");	
	sm4_context context;
	sm4_context* ctx=&context;
	sm4_setkey_dec(ctx,key);//计算轮密钥
	sm4_crypt_ecb_old( ctx, ctx->mode,len,input, output);//解密
	return 0;	
}

int sm4_decrypt_cbc(unsigned char *key,unsigned char *input,unsigned char *output,u16 len,u8 flag)
{
    printf("\r\n***************** SM4_CBC *****************\r\n");	
//	unsigned char key[16]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}; // 密钥 
    unsigned char iv[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}; 
	unsigned char iv1[16];
	sm4_context context;
	sm4_context* ctx=&context;
	sm4_setkey_dec(ctx,key);//计算轮密钥
	if(flag!=0)
	{
		for(u8 i=0;i<16;i++)
			iv1[i]=input[i];
		sm4_crypt_cbc_old( ctx, ctx->mode,len, iv1,input+16, output);//解密
	}
	else
		sm4_crypt_cbc_old( ctx, ctx->mode,len, iv,input, output);//解密
	return 0;
}
