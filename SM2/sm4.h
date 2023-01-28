/**
 * \file sm4.h
 */
#ifndef XYSSL_SM4_H
#define XYSSL_SM4_H

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0
#include "sm2.h"

/**
 * \brief          SM4 context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned long sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM4 key schedule (128-bit, encryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );

/**
 * \brief          SM4 key schedule (128-bit, decryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );

/**
  * @brief SM4 + PKCS7算法
	* @param ctx:      SM4结构体，主要是包含初始秘钥（对于ECB模式的加密来说，
										 不同之处就在于它的初始化时秘钥的初始方法不同,加密操作
										 都是一样的）
	* @param mode:     加密：SM4_ENCRYPT 解密：SM4_DECRYPT
	* @param length:   需要处理的数据长度指针
	* @param input:    需要处理的数据
	* @param output:   处理完的数据
	* @attention：     1、length参数类型为指针，在此函数内部，该参数会
										 被修改为加解密后数据的实际长度。
										 2、对于input参数，要求其必须富裕出至少16字节的空间以供
										填充数据。
										 3、对于解密的output，并未真正去除掉填充的数据，只是
										对数据长度进行去填充长度操作，请按length长度取值
  * @retval void
  */
void sm4_crypt_ecb( sm4_context *ctx, int mode, unsigned int *length, \
										unsigned char *input, unsigned char *output);


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
										2、对于input参数，要求其必须富裕出至少16字节的空间以供
										填充数据。
										3、对于解密的output，并未真正去除掉填充的数据，只是
										对数据长度进行去填充长度操作，请按length长度取值
  * @retval void
 */
void sm4_crypt_cbc( sm4_context *ctx,int mode,unsigned int *length, unsigned char iv[16], \
                    unsigned char *input,unsigned char *output );
int sm4_test_ecb(TEXT *tx);
int sm4_test_cbc(TEXT *tx);
int sm4_encrypt_ecb(unsigned char *txcontent,unsigned char *rxcontent);
int sm4_encrypt_cbc(unsigned char *txcontent,unsigned char *rxcontent);
#ifdef __cplusplus
}
#endif

#endif /* sm4.h */

