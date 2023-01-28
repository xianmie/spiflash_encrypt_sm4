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
  * @brief SM4 + PKCS7�㷨
	* @param ctx:      SM4�ṹ�壬��Ҫ�ǰ�����ʼ��Կ������ECBģʽ�ļ�����˵��
										 ��֮ͬ�����������ĳ�ʼ��ʱ��Կ�ĳ�ʼ������ͬ,���ܲ���
										 ����һ���ģ�
	* @param mode:     ���ܣ�SM4_ENCRYPT ���ܣ�SM4_DECRYPT
	* @param length:   ��Ҫ��������ݳ���ָ��
	* @param input:    ��Ҫ���������
	* @param output:   �����������
	* @attention��     1��length��������Ϊָ�룬�ڴ˺����ڲ����ò�����
										 ���޸�Ϊ�ӽ��ܺ����ݵ�ʵ�ʳ��ȡ�
										 2������input������Ҫ������븻ԣ������16�ֽڵĿռ��Թ�
										������ݡ�
										 3�����ڽ��ܵ�output����δ����ȥ�����������ݣ�ֻ��
										�����ݳ��Ƚ���ȥ��䳤�Ȳ������밴length����ȡֵ
  * @retval void
  */
void sm4_crypt_ecb( sm4_context *ctx, int mode, unsigned int *length, \
										unsigned char *input, unsigned char *output);


/**
	* @brief          SM4-CBC + PKCS7�㷨
	* @param ctx      SM4 context
	* @param mode     ���ܣ�SM4_ENCRYPT ���ܣ�SM4_DECRYPT
	* @param length   ��Ҫ��������ݳ���ָ��
	* @param iv       ��ʼ������(ʹ�ú����)
	* @param input:   ��Ҫ���������
	* @param output:  �����������
	* @attention��    1��length��������Ϊָ�룬�ڴ˺����ڲ����ò�����
										 ���޸�Ϊ�ӽ��ܺ����ݵ�ʵ�ʳ��ȡ�
										2������input������Ҫ������븻ԣ������16�ֽڵĿռ��Թ�
										������ݡ�
										3�����ڽ��ܵ�output����δ����ȥ�����������ݣ�ֻ��
										�����ݳ��Ƚ���ȥ��䳤�Ȳ������밴length����ȡֵ
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

