#include <stdlib.h>
#include "stdint.h"
#include "miracl.h"
#include "sm2.h"
#include "sm3.h"
#include "usart.h"
#include "string.h"


#define SM2_PAD_ZERO TRUE
//#define SM2_PAD_ZERO FALSE
 
#define MAXLEN 32 //ÿ������������󳤶�32byte
#define IDLEN 18 //�û�id��ռλ��byte

struct FPECC{
char *p;
char *a;
char *b;
char *n;
char *x;
char *y;
};
 
/*SM2*/
struct FPECC Ecc256={
"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
};

 
 
#define SEED_CONST 0x1BD8C95A

void PrintBuf(unsigned char *buf, int	buflen)
{
	int i;
	printf("\r\n");
	printf("len = %d\r\n", buflen);
	for(i=0; i<buflen; i++) {
  	if (i % 32 != 31)
  	  printf("%02x", buf[i]);
  	  else
  	  printf("%02x\r\n", buf[i]);
  }
  printf("\r\n");
  return;
}
 
void Printch(unsigned char *buf, int	buflen)
{
	int i;
	for (i = 0; i < buflen; i++) {
		if (i % 32 != 31)
			printf("%c", buf[i]);
		else
			printf("%c\n", buf[i]);
	}
	printf("\n");
	//return 0;
}
/**
	* @brief ����SM2��˽Կ��
	* @param wx��         ��Կ��X���꣬����32�ֽ���ǰ���0x00
	* @param wxlen:       wx���ֽ�����32
	* @param wy��         ��Կ��Y���꣬����32�ֽ���ǰ���0x00
	* @param wylen:       wy���ֽ�����32
	* @param privkey��    ˽Կ������32�ֽ���ǰ���0x00
	* @param privkeylen�� privkey���ֽ�����32
  * @retval void
  */
void sm2_keygen(unsigned char *wx, int *wxlen, unsigned char *wy, \
	              int *wylen, unsigned char *privkey, int *privkeylen)
{
	struct FPECC *cfig = &Ecc256;
	epoint *g;
	big a,b,p,n,x,y,key1;
	
	miracl instance;
	miracl *mip = &instance;

	char mem[MR_BIG_RESERVE(7)];
	memset(mem, 0, MR_BIG_RESERVE(7));
	
	mip = mirsys(mip, 20, 0);   /* Use Hex Internally */
	mip->IOBASE = 16;

	p = mirvar_mem(mip, mem, 0);
	a = mirvar_mem(mip, mem, 1);
	b = mirvar_mem(mip, mem, 2);
	n = mirvar_mem(mip, mem, 3);
	x = mirvar_mem(mip, mem, 4);
	y = mirvar_mem(mip, mem, 5);
	key1 = mirvar_mem(mip, mem, 6);

	cinstr(mip, p, cfig->p);
	cinstr(mip, a, cfig->a);
	cinstr(mip, b, cfig->b);
	cinstr(mip, n, cfig->n);
	cinstr(mip, x, cfig->x);
	cinstr(mip, y, cfig->y);

	ecurve_init(mip, a, b, p, MR_PROJECTIVE);

	char mem1[MR_ECP_RESERVE(1)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(1));
	
    g = epoint_init_mem(mip, mem1, 0);
	epoint_set(mip, x, y, 0, g);
	
	do
	{
		irand(mip, SEED_CONST+TIM_GetCounter(TIM3));
		bigrand(mip, n, key1);
	} while (key1->len == 0);//�����������key1
	
	ecurve_mult(mip, key1,g,g);
	epoint_get(mip, g,x,y); /* compress point */
	
	*wxlen = big_to_bytes(mip, 32, x, (char *)wx, TRUE);
	*wylen = big_to_bytes(mip, 32, y, (char *)wy, TRUE);
	*privkeylen = big_to_bytes(mip, 32, key1, (char *)privkey, TRUE);

	/* clear all memory used */
  memset(mem,0,MR_BIG_RESERVE(7));
  memset(mem1,0,MR_ECP_RESERVE(1));
	mirexit(mip);
}

/**
  * @brief  ��Կ��������
  * @param  zl  Ҫ��������ݡ���list��x��
  * @param  zr  Ҫ��������ݡ���row��y��
  * @param  keylen  ��Ҫ�����õ��ĳ���
  * @param  kbuf    ����󷵻ص����ݣ�������ֵ��,����ռ�����Ϊ��Ҫkeylen
  * @retval 0���ɹ� ����ʧ��
  */
int kdf(unsigned char *zl, unsigned char *zr, int klen, unsigned char *kbuf)
{

	unsigned char buf[70];
	unsigned char digest[32];
	uint32_t ct = 1; //��ʼ��һ��32���ع��ɵļ�����ct
	int i, m, n;
	unsigned char *p;
	
	memcpy(buf, zl, 32);//ȡzl��ǰ32λ����buf[0:31]
	memcpy(buf+32, zr, 32);//ȡzr��ǰ32λ����buf[32:63]
	m = klen / 32;//������ݳ���/32
	n = klen % 32;//������ݳ���ȡ��
	p = kbuf;
	
	buf[64] = (ct >> 24) & 0xFF;
	buf[65] = (ct >> 16) & 0xFF;
	buf[66] = (ct >> 8) & 0xFF;
	buf[67] = ct & 0xFF;
	
	for(i = 1; i < m+1; i++)//��i=1��floor(klen/v)
	{
		SM3Calc(buf, 68, p);//����Hashi(Z||ct),���������p��
		p += 32;
		ct++;
	}
	
	if(n != 0)//���klen/v��������
	{
		SM3Calc(buf, 68, digest);//����ժҪ
	}
		
	memcpy(p, digest, n);//���������򲻸ı䣬���������������ժҪ

	for(i = 0; i < klen; i++)
	{
		if(kbuf[i] != 0)
			break;
	}
 
	if(i < klen)
		return 1;
	else
		return 0;//���kbuf��ǰklenλȫΪ0����0
}

/**
  * @brief  SM2����
  * @param  msg��    Ҫ���ܵ���������
  * @param  msglen�� �������ݳ���
  * @param  wx��     ��Կ��x����
  * @param  wxlen��  ��Կ��x���곤�ȣ�������32
  * @param  wy��     ��Կ��y����
  * @param  wylen��  ��Կ��y���곤�ȣ�������32
  * @param  outmsg�� ���ܺ����� ����Ϊ���� + 96
  * @retval -1��ʧ�� msglen + 96���ɹ�
  */
int sm2_encrypt(unsigned char *msg,int msglen, unsigned char *wx,int wxlen, \
	              unsigned char *wy,int wylen, unsigned char *outmsg)
{
 
	struct FPECC *cfig = &Ecc256;
	big x2, y2, c1, c2, k;
	big a,b,p,n,x,y;
	epoint *g, *w;
	int ret = -1;
	int i;
	unsigned char zl[32], zr[32];
	unsigned char *tmp;
	
	miracl instance;
  miracl *mip = &instance;

	tmp = malloc(msglen+64);//�����СΪ���ĳ���+64���ڴ�
	if(tmp == NULL)
		return -1;
	
	mip = mirsys(mip, 20, 0);   //��ʼ������ϵͳ
	mip->IOBASE = 16;
	
	char mem[MR_BIG_RESERVE(11)];//���������Դ��12������
  memset(mem, 0, MR_BIG_RESERVE(11));
	
	p= mirvar_mem(mip, mem, 0);//��ʼ����������
	a=mirvar_mem(mip, mem, 1);
	b=mirvar_mem(mip, mem, 2);
	n=mirvar_mem(mip, mem, 3);
	x=mirvar_mem(mip, mem, 4);
	y=mirvar_mem(mip, mem, 5);
	k=mirvar_mem(mip, mem, 6);
	x2=mirvar_mem(mip, mem, 7);
	y2=mirvar_mem(mip, mem, 8);
	c1=mirvar_mem(mip, mem, 9);
	c2=mirvar_mem(mip, mem, 10);
	
	cinstr(mip, p,cfig->p);//���ַ���ת��Ϊ����
	cinstr(mip, a,cfig->a);
	cinstr(mip, b,cfig->b);
	cinstr(mip, n,cfig->n);
	cinstr(mip, x,cfig->x);
	cinstr(mip, y,cfig->y);
	
	ecurve_init(mip, a,b,p,MR_PROJECTIVE);//��ʼ����Բ����

	char mem1[MR_ECP_RESERVE(2)]; //���������Դ��g��w����
	memset(mem1 ,0, MR_ECP_RESERVE(2));

	g = epoint_init_mem(mip, mem1,0);//��ʼ����Բ�ϵĵ�
	w = epoint_init_mem(mip, mem1,1);
	 
    epoint_set(mip, x,y,0,g);//g=(x,y)Ϊ����G,��x��yΪ�ṹ��ECC256�е�ֵ
	bytes_to_big(mip, wxlen,(char *)wx,x);//����Կֵ����x��y
	bytes_to_big(mip, wylen,(char *)wy,y);
	epoint_set(mip, x,y,0,w);//��w=(x,y),��x��yΪ��Կ��ֵ
		
sm2_encrypt_again:
	do
	{
		irand(mip, SEED_CONST+TIM_GetCounter(TIM3));
		bigrand(mip, n, k);
	} while (k->len == 0);//�����������k
	
	//����C1
	ecurve_mult(mip, k, g, g);//g=[k]g
	epoint_get(mip, g, c1, c2);//��g������ȡ������c1,c2
	big_to_bytes(mip, 32, c1, (char *)outmsg, TRUE);//��g��x����ת��Ϊ�ַ�����Ϊ���ܺ�����[0:31]
	big_to_bytes(mip, 32, c2, (char *)outmsg+32, TRUE);//��g��y����ת��Ϊ�ַ�����Ϊ���ܺ�����[32:63]
	
	//����S=[h]PB;��SΪ����Զ���򱨴��˳�
	if(point_at_infinity(w))
		goto exit_sm2_encrypt;
	
	//������Բ���ߵ�[k]PB
	ecurve_mult(mip, k, w, w);//w=[k]w
	epoint_get(mip, w, x2, y2);//x2=w(x),y2=w(y)
	big_to_bytes(mip, 32, x2, (char *)zl, TRUE);//��w��x��y����ת��Ϊ�ַ����󸳸�zl��zr
	big_to_bytes(mip, 32, y2, (char *)zr, TRUE);
	//����t = KDF,���tȫ��,����A1
	if (kdf(zl, zr, msglen, outmsg+64+32) == 0)
		goto sm2_encrypt_again;
	//����C2=M���t,(t��outmsg[64+32:64+32+msglen])
	for(i = 0; i < msglen; i++)
	{
		outmsg[64+32+i] ^= msg[i];//�˲���C2=outmsg[64:64+msglen]
	}
	//����C3
	memcpy(tmp, zl, 32);//tmp=x2||msg||y2
	memcpy(tmp+32, msg, msglen);
	memcpy(tmp+32+msglen, zr, 32);
	SM3Calc(tmp, 64+msglen, &outmsg[64]);//C3=Hash(tmp)
	//C=C1||C3||C2,��outmsg[0:63]=C1;outmsg[64:95]=C3;outmsg[96:96+msg]=C2
	ret = msglen+64+32;
	
exit_sm2_encrypt:

	memset(mem,0,MR_BIG_RESERVE(11));
	memset(mem1,0,MR_ECP_RESERVE(2));
	mirexit(mip);
	free(tmp);
	return ret;
}
 
/**
* @brief  SM2����
* @param  msg��        Ҫ���ܵ���������
* @param  msglen��     �������ݳ���
* @param  privkey��    ˽Կ
* @param  privkeylen�� ˽Կ����
* @param  outmsg�� ���ܺ������ ����Ϊ���� - 96
* @retval -1��ʧ�� msglen - 96���ɹ�
*/
int sm2_decrypt(unsigned char *msg,int msglen, unsigned char *privkey, \
	              int privkeylen, unsigned char *outmsg)
{
 
	struct FPECC *cfig = &Ecc256;
	big x2, y2;
	big a,b,p,n,x,y,key1;
	epoint *g;
	unsigned char c3[32];
	unsigned char zl[32], zr[32];
	int i, ret = -1;
	unsigned char *tmp;
	
	miracl instance;
	miracl *mip = &instance;
	
	if(msglen < 96)//����<96����ܺ�����������⣬�˳�����
		return 0;
	msglen -= 96;//��ȥ96�õ�ֻ��������Ϣ�����ݳ���
	tmp = malloc(msglen+64);
	if(tmp == NULL)
		return 0;
	
	mip = mirsys(mip, 20, 0);   
	mip->IOBASE = 16;
 
	char mem[MR_BIG_RESERVE(9)];
  memset(mem, 0, MR_BIG_RESERVE(9));
 
	x2 = mirvar_mem(mip, mem, 0);//��ʼ����������
	y2 = mirvar_mem(mip, mem, 1);
	p = mirvar_mem(mip, mem, 2);
	a = mirvar_mem(mip, mem, 3);
	b = mirvar_mem(mip, mem, 4);
	n = mirvar_mem(mip, mem, 5);
	x = mirvar_mem(mip, mem, 6);
	y = mirvar_mem(mip, mem, 7);
	key1 = mirvar_mem(mip, mem, 8);
	
	bytes_to_big(mip, privkeylen,(char *)privkey,key1);//��˽Կת��Ϊ����������key1
	
	cinstr(mip, p,cfig->p);//���ַ���ת��Ϊ��������p��a...y
	cinstr(mip, a,cfig->a);
	cinstr(mip, b,cfig->b);
	cinstr(mip, n,cfig->n);
	cinstr(mip, x,cfig->x);
	cinstr(mip, y,cfig->y);
	
	ecurve_init(mip, a,b,p,MR_PROJECTIVE);//��ʼ����Բ����

	char mem1[MR_ECP_RESERVE(1)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(1));

	g = epoint_init_mem(mip, mem1,0);
	
    //B1:ȡ��C1,��֤C1�Ƿ�������Բ���߷���
	bytes_to_big(mip, 32, (char *)msg, x);//���ܺ����е�c1,c2����x,y
	bytes_to_big(mip, 32, (char *)msg+32, y);   	
    if(!epoint_set(mip, x,y,0,g))//����(c1,c2)�Ƿ�����Բ������,����g=C1
		goto exit_sm2_decrypt; 		
	
	//B2:��SΪ����Զ���򱨴��˳�	
	if(point_at_infinity(g))//����S�����S=[h]C1������Զ���򷵻�
		goto exit_sm2_decrypt;  
	
	//B3:����[dB]C1=(x2,y2),��ת��Ϊ�ַ���
	ecurve_mult(mip, key1, g, g);//g=g[dB]
	epoint_get(mip, g, x2, y2);	//x2=g(x),y2=g(y)
	big_to_bytes(mip, 32, x2, (char *)zl, TRUE);//ת��Ϊ�ַ�����zl=x2,zr=y2
	big_to_bytes(mip, 32, y2, (char *)zr, TRUE); 
	
	//B4:����t=KDF(x2||y2,klen),��tȫΪ0�򱨴��˳�
	if (kdf(zl, zr, msglen, outmsg) == 0)
		goto exit_sm2_decrypt; 
	
	//B5������M��outsmg,M=C2���t
	for(i = 0; i < msglen; i++)
	{
		outmsg[i] ^= msg[i+96];
	}   
	
	//����u=Hash(x2||M'||y2),��t!=C3�򱨴��˳�
	memcpy(tmp, zl, 32);//tmp=zl||outmsg||zr
	memcpy(tmp+32, outmsg, msglen);
	memcpy(tmp+32+msglen, zr, 32);
	
	SM3Calc(tmp, 64+msglen, c3);//����u
	if(memcmp(c3, msg+64, 32) != 0)
	{
		goto exit_sm2_decrypt;
	}
	
	ret =  msglen;
exit_sm2_decrypt:
	memset(mem,0,MR_BIG_RESERVE(9));
	memset(mem1,0,MR_ECP_RESERVE(1));
	mirexit(mip);
	free(tmp);
	return ret;
}
/**
* @brief  SM2ǩ��
* @param  msg����ǩ������
* @param  msglen����ǩ�����ĳ���
* @param  id���û�Id
* @param  wx���û���Կx����
* @param  wy���û���Կy����
* @param  dB���û�˽Կ
* @param  msgsigned��ǩ���������
* @retval 0���������� 
*/
int sm2_sign(unsigned char *msg,int msglen,unsigned char *id,unsigned char *wx,unsigned char *wy,\
            unsigned char *dB,unsigned char *msgsigned)
{
	struct FPECC *cfig = &Ecc256;
	epoint *g;
	big a,b,p,n,x,y;
	big e,x1,y1,rk,t1,t2,s1,r1,db,k;
	unsigned char bufza[192+IDLEN+2];//32*6+18+2
	unsigned char idlen[2]={0x00,0x90};//18*8=144 bit
	unsigned char aa[32];
	unsigned char bb[32];
	unsigned char xx[32];
	unsigned char yy[32];
	unsigned char za[32];
	unsigned char ee[32];
	unsigned char msg1[32+MAXLEN];//MAXLEN=32,�����һ�ο�ǩ��32byte��������Ϣ
	unsigned char r[32];
	unsigned char s[32];

	
	miracl instance;
	miracl *mip = &instance;

	char mem[MR_BIG_RESERVE(17)];
	memset(mem, 0, MR_BIG_RESERVE(17));
	
	mip = mirsys(mip, 20, 0);   /* Use Hex Internally */
	mip->IOBASE = 16;
	
	p = mirvar_mem(mip, mem, 0);
	a = mirvar_mem(mip, mem, 1);
	b = mirvar_mem(mip, mem, 2);
	n = mirvar_mem(mip, mem, 3);
	x = mirvar_mem(mip, mem, 4);
	y = mirvar_mem(mip, mem, 5);
	x1 = mirvar_mem(mip, mem, 6);
	y1 = mirvar_mem(mip, mem, 7);
	rk = mirvar_mem(mip, mem, 9);
	t1 = mirvar_mem(mip, mem, 10);
	t2 = mirvar_mem(mip, mem, 11);
	s1 = mirvar_mem(mip, mem, 12);
	r1 = mirvar_mem(mip, mem, 13);
	db = mirvar_mem(mip, mem, 14);
	k = mirvar_mem(mip, mem, 15);
	e = mirvar_mem(mip, mem, 16);
//��64byte���ַ���ת����32byte	
	cinstr(mip, p, cfig->p);
	cinstr(mip, a, cfig->a);
	cinstr(mip, b, cfig->b);
	cinstr(mip, n, cfig->n);
	cinstr(mip, x, cfig->x);
	cinstr(mip, y, cfig->y);
	
	big_to_bytes(mip, 32, a, (char *)aa, TRUE);
	big_to_bytes(mip, 32, b, (char *)bb, TRUE);
	big_to_bytes(mip, 32, x, (char *)xx, TRUE);//g���xֵ
	big_to_bytes(mip, 32, y, (char *)yy, TRUE);

//����ZA
	memcpy(bufza,idlen,2);
	memcpy(bufza+2,id,IDLEN);
	memcpy(bufza+2+IDLEN,aa,32);
	memcpy(bufza+2+IDLEN+32,bb,32);
	memcpy(bufza+2+IDLEN+64,xx,32);
	memcpy(bufza+2+IDLEN+96,yy,32);
	memcpy(bufza+2+IDLEN+128,wx,32);
	memcpy(bufza+2+IDLEN+160,wy,32);
	
	SM3Calc(bufza,192+IDLEN+2, za);
//��ʼ����Բ����
	ecurve_init(mip, a, b, p, MR_PROJECTIVE);

	char mem1[MR_ECP_RESERVE(1)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(1));
	
    g = epoint_init_mem(mip, mem1, 0);
	epoint_set(mip, x, y, 0, g);//����G��
//A2:����e=H(ZA||M)	
	memcpy(msg1,za,32);
	memcpy(msg1+32,msg,msglen);
	SM3Calc(msg1, 32+msglen, ee);
	bytes_to_big(mip, 32, (char *)ee, e);//���ַ���ת��Ϊ����
//A3	
A3:	
	do
	{
		irand(mip, SEED_CONST+TIM_GetCounter(TIM3));
		bigrand(mip, n, k);
	} while (size(k)==0);//�����������k

//A4:����(x1,y1)=k[G]
	ecurve_mult(mip, k, g, g);//g=[k]g
	epoint_get(mip, g, x1, y1);//��g������ȡ������x1,y1

//A5:����r=(e+x1)mod n 
	add(mip,e,x1,r1);//r=e+x1
	divide (mip,r1,n,n);//r=r (mod n)=(e+x1)mod n
	add(mip,r1,k,rk);
	if((size(r1)==0)||(!mr_compare(rk,n)))
		goto A3;
	big_to_bytes(mip, 32, r1, (char *)r, TRUE);
//A6:����s=((1+dB)^(-1)*(k-r*dB))mod n

	bytes_to_big(mip, 32, (char *)dB, db);
	incr(mip,db, 1, t1);//t1=1+dB
	xgcd(mip,t1, n, t1, t1, t1);//t1=(t1^(-1))mod n
	multiply(mip,r1, db, t2);//t2=r*dB
	divide(mip,t2, n, n);//t2=t2 mod n
	subtract(mip,k, t2, t2);//t2=k-t2
	add(mip,t2, n, t2);//t2=t2+n
	multiply(mip,t1, t2, s1);//s1=t1*t2
	divide(mip,s1, n, n);//s1= s1 mod n 

	if(!size(s1))
		goto A3;
	big_to_bytes(mip, 32, s1, (char *)s, TRUE);

	printf("\r\nr:");
    PrintBuf(r,32);
	printf("s:");
    PrintBuf(s,32);
	memcpy(msgsigned,msg,msglen);
	memcpy(msgsigned+msglen,r,32);
	memcpy(msgsigned+msglen+32,s,32);
	
//exit_sm2_sign:
	memset(mem,0,MR_BIG_RESERVE(17));
	memset(mem1,0,MR_ECP_RESERVE(1));
	mirexit(mip);
	return 0;
}
/**
* @brief  SM2��ǩ
* @param  msg������
* @param  msglen�����ĳ���
* @param  id���û�Id
* @param  wx���û���Կx����
* @param  wy���û���Կy����
* @param  r,s��ǩ��
* @retval 0:��֤ͨ��,1:��֤ʧ�� 
*/
int sm2_vrisign(unsigned char *msg,int msglen,unsigned char *id,unsigned char *wx,unsigned char *wy,\
            unsigned char *r,unsigned char *s)
{
	struct FPECC *cfig = &Ecc256;
	big a,b,p,n,x,y;
	big rr,ss,e,x1,y1,R,t,px,py;
	epoint *g, *w;
	unsigned char bufza[192+IDLEN+2];//����id����Ϊ4byte
	unsigned char idlen[2]={0x00,0x90};
	unsigned char aa[32];
	unsigned char bb[32];
	unsigned char xx[32];
	unsigned char yy[32];
	unsigned char za[32];
	unsigned char ee[32];
	unsigned char msg1[32+MAXLEN];//MAXLEN=128=64+32+32,�����һ�ο�ǩ��256bit��������Ϣ
	
	miracl instance;
    miracl *mip = &instance;
	
	mip = mirsys(mip, 20, 0);   //��ʼ������ϵͳ
	mip->IOBASE = 16;
	
	char mem[MR_BIG_RESERVE(15)];
    memset(mem, 0, MR_BIG_RESERVE(15));
	
	p= mirvar_mem(mip, mem, 0);//��ʼ����������
	a=mirvar_mem(mip, mem, 1);
	b=mirvar_mem(mip, mem, 2);
	n=mirvar_mem(mip, mem, 3);
	x=mirvar_mem(mip, mem, 4);
	y=mirvar_mem(mip, mem, 5);
	rr=mirvar_mem(mip, mem, 6);
	ss=mirvar_mem(mip, mem, 7);	
	e=mirvar_mem(mip, mem, 8);
	x1=mirvar_mem(mip, mem, 9);
	y1=mirvar_mem(mip, mem, 10);

	R=mirvar_mem(mip, mem, 11);
	t=mirvar_mem(mip, mem, 12);
	px=mirvar_mem(mip, mem, 13);
	py=mirvar_mem(mip, mem, 14);
	
	cinstr(mip, p,cfig->p);//���ַ���ת��Ϊ����
	cinstr(mip, a,cfig->a);
	cinstr(mip, b,cfig->b);
	cinstr(mip, n,cfig->n);
	cinstr(mip, x,cfig->x);
	cinstr(mip, y,cfig->y);
	
	big_to_bytes(mip, 32, a, (char *)aa, TRUE);
	big_to_bytes(mip, 32, b, (char *)bb, TRUE);
	big_to_bytes(mip, 32, x, (char *)xx, TRUE);//g���xֵ
	big_to_bytes(mip, 32, y, (char *)yy, TRUE);
	
//B1,B2����֤r',s'�Ƿ�����[1,n-1]
	bytes_to_big(mip, 32, (char *)r, rr);	
	if((size(rr)<1)||!(mr_compare(n,rr)))
		goto verify_fail;
	bytes_to_big(mip, 32, (char *)s, ss);	
	if((size(ss)<1)||!(mr_compare(n,ss)))
		goto verify_fail;

//����ZA
	memcpy(bufza,idlen,2);
	memcpy(bufza+2,id,IDLEN);
	memcpy(bufza+2+IDLEN,aa,32);
	memcpy(bufza+2+IDLEN+32,bb,32);
	memcpy(bufza+2+IDLEN+64,xx,32);
	memcpy(bufza+2+IDLEN+96,yy,32);
	memcpy(bufza+2+IDLEN+128,wx,32);
	memcpy(bufza+2+IDLEN+160,wy,32);
	
	SM3Calc(bufza,192+IDLEN+2, za);
	
//��ʼ����Բ����	
	ecurve_init(mip, a,b,p,MR_PROJECTIVE);
	char mem1[MR_ECP_RESERVE(2)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(2));	
    g = epoint_init_mem(mip, mem1, 0);
	w = epoint_init_mem(mip, mem1, 1);
	epoint_set(mip, x, y, 0, g);//����G��
	bytes_to_big(mip, 32,(char *)wx,px);//����Կֵ����px��py
	bytes_to_big(mip, 32,(char *)wy,py);
	epoint_set(mip, px,py,0,w);//���ù�ԿP��
	
//B3��B4:����e'=H(ZA||M')	
	memcpy(msg1,za,32);
	memcpy(msg1+32,msg,msglen);
	SM3Calc(msg1, 32+msglen, ee);
	bytes_to_big(mip, 32, (char *)ee, e);//���ַ���ת��Ϊ����
//B5:����t=(r'+s') mod n,��t=0����֤��ͨ��
	add(mip,rr,ss,t);//t=r'+s'
	divide(mip,t,n,n);//t=t (mod n)=(r'+s')mod n	
	if(size(t)==0)
		goto verify_fail;
//B6:����(x1',y1')=[s']G+[t]P
	ecurve_mult(mip, ss, g, g);//G=[s']G
	ecurve_mult(mip,t,w,w);//P=[t]P
	ecurve_add(mip,g, w);
	epoint_get(mip,w, x1, y1);

	
//B7:����R=(e'+x1')	mod n,��֤R=r'�Ƿ����
	add(mip,e,x1,R);//R=e'+x1'
	divide (mip,R,n,n);//R=R (mod n)=(e'+x1')mod n	

	if(!mr_compare(R,rr))
		goto verify_pass;

verify_fail:
	printf("\r\nverify fail!\r\n");
	memset(mem,0,MR_BIG_RESERVE(15));
	memset(mem1,0,MR_ECP_RESERVE(2));
	mirexit(mip);
	return 1;

verify_pass:
	printf("\r\nverify pass!\r\n");
	memset(mem,0,MR_BIG_RESERVE(15));
	memset(mem1,0,MR_ECP_RESERVE(2));
	mirexit(mip);
	return 0;	
		
}
/**
* @brief  SM2�ӽ��ܲ���
* @param  tx��        ��������Ľṹ��
* @retval 0���������� 
*/
int sm2_encrypt_test(TEXT *tx)
{	
	printf("\r\n******************* SM2 *******************\r\n");
	unsigned char dB[32];   //���˽Կ
	unsigned char xB[32];   //��Ź�Կpb��x��y��
	unsigned char yB[32];
	unsigned char msgsigned[320];//256+64
	unsigned char etx[256];
	unsigned char mtx[256];
	unsigned char id[IDLEN]={0x41,0x4C,0x49,0x43,0x45,0x31,0x32,0x33,0x40,0x59,0x41,0x48,0x4F,0x4F,0x2E,0x43,0x4F,0x4D};

	int wxlen, wylen, privkeylen,ret,etxlen;

    
	sm2_keygen(xB, &wxlen, yB, &wylen, dB, &privkeylen);
	printf("\r\nPrivate key�� ");
	PrintBuf(dB, 32);
	printf("Public key x�� ");
	PrintBuf(xB, 32);
	printf("Public key y�� ");
	PrintBuf(yB, 32);
		
	printf("\n`````````````````` Plaintext ```````````````````\n");
	PrintBuf(tx->content, tx->len);

	printf("\n`````````````````` Sign ``````````````````\n");
	sm2_sign(tx->content,tx->len,id,xB,yB,dB,msgsigned);

	printf("\n`````````````````` Ciphertext ```````````````````\n");
	etxlen=sm2_encrypt(msgsigned,(tx->len)+64,xB,32,yB,32,etx);	
	PrintBuf(etx,etxlen );

	printf("\n`````````````````` After Decrypt ```````````````````\n");
	ret = sm2_decrypt(etx,etxlen,dB,32,mtx);
	if( ret < 0)
		printf("sm2_decrypt error!\n");
	else
	{
		PrintBuf(mtx, tx->len);
		printf("\r\nr and s:");
		PrintBuf(mtx+(tx->len),64);
	}	
 
 	printf("\n`````````````````` Verify ``````````````````\n");	
	sm2_vrisign(mtx,tx->len,id,xB,yB,mtx+(tx->len),mtx+(tx->len)+32);
	return 0;
}

int sm2_encrypt_test_nosign(TEXT *tx)
{	
	printf("\r\n******************* SM2 without sign *******************\r\n");
	unsigned char dB[32];   //���˽Կ
	unsigned char xB[32];   //��Ź�Կpb��x��y��
	unsigned char yB[32];
	unsigned char etx[256];
	unsigned char mtx[256];
	int wxlen, wylen, privkeylen,ret,etxlen;
  
	sm2_keygen(xB, &wxlen, yB, &wylen, dB, &privkeylen);
	printf("\r\nPrivate key�� ");
	PrintBuf(dB, 32);
	printf("Public key x�� ");
	PrintBuf(xB, 32);
	printf("Public key y�� ");
	PrintBuf(yB, 32);
		
	printf("\n`````````````````` Plaintext ```````````````````\n");
	PrintBuf(tx->content, tx->len);

	printf("\n`````````````````` Ciphertext ```````````````````\n");
	etxlen=sm2_encrypt(tx->content,tx->len,xB,32,yB,32,etx);	
	PrintBuf(etx,etxlen );

	printf("\n`````````````````` After Decrypt ```````````````````\n");
	ret = sm2_decrypt(etx,etxlen,dB,32,mtx);
	if( ret < 0)
		printf("sm2_decrypt error!\n");
	else
	{
		PrintBuf(mtx, tx->len);
	}	

	return 0;
}
