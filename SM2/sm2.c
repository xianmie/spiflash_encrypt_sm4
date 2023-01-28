#include <stdlib.h>
#include "stdint.h"
#include "miracl.h"
#include "sm2.h"
#include "sm3.h"
#include "usart.h"
#include "string.h"


#define SM2_PAD_ZERO TRUE
//#define SM2_PAD_ZERO FALSE
 
#define MAXLEN 32 //每次输入明文最大长度32byte
#define IDLEN 18 //用户id所占位数byte

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
	* @brief 生成SM2公私钥对
	* @param wx：         公钥的X坐标，不足32字节在前面加0x00
	* @param wxlen:       wx的字节数，32
	* @param wy：         公钥的Y坐标，不足32字节在前面加0x00
	* @param wylen:       wy的字节数，32
	* @param privkey：    私钥，不足32字节在前面加0x00
	* @param privkeylen： privkey的字节数，32
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
	} while (key1->len == 0);//生成随机大数key1
	
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
  * @brief  密钥派生函数
  * @param  zl  要处理的数据——list（x）
  * @param  zr  要处理的数据——row（y）
  * @param  keylen  需要派生得到的长度
  * @param  kbuf    计算后返回的内容（二进制值）,分配空间至少为需要keylen
  * @retval 0：成功 其他失败
  */
int kdf(unsigned char *zl, unsigned char *zr, int klen, unsigned char *kbuf)
{

	unsigned char buf[70];
	unsigned char digest[32];
	uint32_t ct = 1; //初始化一个32比特构成的计数器ct
	int i, m, n;
	unsigned char *p;
	
	memcpy(buf, zl, 32);//取zl的前32位赋给buf[0:31]
	memcpy(buf+32, zr, 32);//取zr的前32位赋给buf[32:63]
	m = klen / 32;//输出数据长度/32
	n = klen % 32;//输出数据长度取余
	p = kbuf;
	
	buf[64] = (ct >> 24) & 0xFF;
	buf[65] = (ct >> 16) & 0xFF;
	buf[66] = (ct >> 8) & 0xFF;
	buf[67] = ct & 0xFF;
	
	for(i = 1; i < m+1; i++)//从i=1到floor(klen/v)
	{
		SM3Calc(buf, 68, p);//计算Hashi(Z||ct),结果储存在p中
		p += 32;
		ct++;
	}
	
	if(n != 0)//如果klen/v不是整数
	{
		SM3Calc(buf, 68, digest);//计算摘要
	}
		
	memcpy(p, digest, n);//若是整数则不改变，若不是整数则加上摘要

	for(i = 0; i < klen; i++)
	{
		if(kbuf[i] != 0)
			break;
	}
 
	if(i < klen)
		return 1;
	else
		return 0;//如果kbuf的前klen位全为0返回0
}

/**
  * @brief  SM2加密
  * @param  msg：    要加密的明文数据
  * @param  msglen： 明文数据长度
  * @param  wx：     公钥的x坐标
  * @param  wxlen：  公钥的x坐标长度，不超过32
  * @param  wy：     公钥的y坐标
  * @param  wylen：  公钥的y坐标长度，不超过32
  * @param  outmsg： 加密后密文 长度为明文 + 96
  * @retval -1：失败 msglen + 96：成功
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

	tmp = malloc(msglen+64);//分配大小为明文长度+64的内存
	if(tmp == NULL)
		return -1;
	
	mip = mirsys(mip, 20, 0);   //初始化大数系统
	mip->IOBASE = 16;
	
	char mem[MR_BIG_RESERVE(11)];//定义数组以存放12个大数
  memset(mem, 0, MR_BIG_RESERVE(11));
	
	p= mirvar_mem(mip, mem, 0);//初始化大数变量
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
	
	cinstr(mip, p,cfig->p);//将字符串转换为整型
	cinstr(mip, a,cfig->a);
	cinstr(mip, b,cfig->b);
	cinstr(mip, n,cfig->n);
	cinstr(mip, x,cfig->x);
	cinstr(mip, y,cfig->y);
	
	ecurve_init(mip, a,b,p,MR_PROJECTIVE);//初始化椭圆曲线

	char mem1[MR_ECP_RESERVE(2)]; //定义数组以存放g、w两点
	memset(mem1 ,0, MR_ECP_RESERVE(2));

	g = epoint_init_mem(mip, mem1,0);//初始化椭圆上的点
	w = epoint_init_mem(mip, mem1,1);
	 
    epoint_set(mip, x,y,0,g);//g=(x,y)为基点G,此x和y为结构体ECC256中的值
	bytes_to_big(mip, wxlen,(char *)wx,x);//将公钥值传入x和y
	bytes_to_big(mip, wylen,(char *)wy,y);
	epoint_set(mip, x,y,0,w);//点w=(x,y),此x和y为公钥的值
		
sm2_encrypt_again:
	do
	{
		irand(mip, SEED_CONST+TIM_GetCounter(TIM3));
		bigrand(mip, n, k);
	} while (k->len == 0);//生成随机大数k
	
	//计算C1
	ecurve_mult(mip, k, g, g);//g=[k]g
	epoint_get(mip, g, c1, c2);//将g的坐标取出赋给c1,c2
	big_to_bytes(mip, 32, c1, (char *)outmsg, TRUE);//将g的x坐标转换为字符串作为加密后结果的[0:31]
	big_to_bytes(mip, 32, c2, (char *)outmsg+32, TRUE);//将g的y坐标转换为字符串作为加密后结果的[32:63]
	
	//计算S=[h]PB;若S为无穷远点则报错并退出
	if(point_at_infinity(w))
		goto exit_sm2_encrypt;
	
	//计算椭圆曲线点[k]PB
	ecurve_mult(mip, k, w, w);//w=[k]w
	epoint_get(mip, w, x2, y2);//x2=w(x),y2=w(y)
	big_to_bytes(mip, 32, x2, (char *)zl, TRUE);//将w的x、y坐标转换为字符串后赋给zl和zr
	big_to_bytes(mip, 32, y2, (char *)zr, TRUE);
	//计算t = KDF,如果t全零,返回A1
	if (kdf(zl, zr, msglen, outmsg+64+32) == 0)
		goto sm2_encrypt_again;
	//计算C2=M异或t,(t即outmsg[64+32:64+32+msglen])
	for(i = 0; i < msglen; i++)
	{
		outmsg[64+32+i] ^= msg[i];//此步后C2=outmsg[64:64+msglen]
	}
	//计算C3
	memcpy(tmp, zl, 32);//tmp=x2||msg||y2
	memcpy(tmp+32, msg, msglen);
	memcpy(tmp+32+msglen, zr, 32);
	SM3Calc(tmp, 64+msglen, &outmsg[64]);//C3=Hash(tmp)
	//C=C1||C3||C2,即outmsg[0:63]=C1;outmsg[64:95]=C3;outmsg[96:96+msg]=C2
	ret = msglen+64+32;
	
exit_sm2_encrypt:

	memset(mem,0,MR_BIG_RESERVE(11));
	memset(mem1,0,MR_ECP_RESERVE(2));
	mirexit(mip);
	free(tmp);
	return ret;
}
 
/**
* @brief  SM2解密
* @param  msg：        要解密的密文数据
* @param  msglen：     密文数据长度
* @param  privkey：    私钥
* @param  privkeylen： 私钥长度
* @param  outmsg： 解密后的明文 长度为明文 - 96
* @retval -1：失败 msglen - 96：成功
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
	
	if(msglen < 96)//长度<96则加密后的数据有问题，退出报错
		return 0;
	msglen -= 96;//减去96得到只含密文消息的数据长度
	tmp = malloc(msglen+64);
	if(tmp == NULL)
		return 0;
	
	mip = mirsys(mip, 20, 0);   
	mip->IOBASE = 16;
 
	char mem[MR_BIG_RESERVE(9)];
  memset(mem, 0, MR_BIG_RESERVE(9));
 
	x2 = mirvar_mem(mip, mem, 0);//初始化大数变量
	y2 = mirvar_mem(mip, mem, 1);
	p = mirvar_mem(mip, mem, 2);
	a = mirvar_mem(mip, mem, 3);
	b = mirvar_mem(mip, mem, 4);
	n = mirvar_mem(mip, mem, 5);
	x = mirvar_mem(mip, mem, 6);
	y = mirvar_mem(mip, mem, 7);
	key1 = mirvar_mem(mip, mem, 8);
	
	bytes_to_big(mip, privkeylen,(char *)privkey,key1);//将私钥转换为大数并赋给key1
	
	cinstr(mip, p,cfig->p);//将字符串转换为大数赋给p、a...y
	cinstr(mip, a,cfig->a);
	cinstr(mip, b,cfig->b);
	cinstr(mip, n,cfig->n);
	cinstr(mip, x,cfig->x);
	cinstr(mip, y,cfig->y);
	
	ecurve_init(mip, a,b,p,MR_PROJECTIVE);//初始化椭圆曲线

	char mem1[MR_ECP_RESERVE(1)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(1));

	g = epoint_init_mem(mip, mem1,0);
	
    //B1:取出C1,验证C1是否满足椭圆曲线方程
	bytes_to_big(mip, 32, (char *)msg, x);//加密函数中的c1,c2赋给x,y
	bytes_to_big(mip, 32, (char *)msg+32, y);   	
    if(!epoint_set(mip, x,y,0,g))//检验(c1,c2)是否在椭圆曲线上,若在g=C1
		goto exit_sm2_decrypt; 		
	
	//B2:若S为无穷远点则报错并退出	
	if(point_at_infinity(g))//计算S：如果S=[h]C1在无穷远点则返回
		goto exit_sm2_decrypt;  
	
	//B3:计算[dB]C1=(x2,y2),并转换为字符串
	ecurve_mult(mip, key1, g, g);//g=g[dB]
	epoint_get(mip, g, x2, y2);	//x2=g(x),y2=g(y)
	big_to_bytes(mip, 32, x2, (char *)zl, TRUE);//转换为字符串，zl=x2,zr=y2
	big_to_bytes(mip, 32, y2, (char *)zr, TRUE); 
	
	//B4:计算t=KDF(x2||y2,klen),若t全为0则报错退出
	if (kdf(zl, zr, msglen, outmsg) == 0)
		goto exit_sm2_decrypt; 
	
	//B5：计算M到outsmg,M=C2异或t
	for(i = 0; i < msglen; i++)
	{
		outmsg[i] ^= msg[i+96];
	}   
	
	//计算u=Hash(x2||M'||y2),若t!=C3则报错退出
	memcpy(tmp, zl, 32);//tmp=zl||outmsg||zr
	memcpy(tmp+32, outmsg, msglen);
	memcpy(tmp+32+msglen, zr, 32);
	
	SM3Calc(tmp, 64+msglen, c3);//计算u
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
* @brief  SM2签名
* @param  msg：待签名明文
* @param  msglen：待签名明文长度
* @param  id：用户Id
* @param  wx：用户公钥x坐标
* @param  wy：用户公钥y坐标
* @param  dB：用户私钥
* @param  msgsigned：签名后的明文
* @retval 0：正常返回 
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
	unsigned char msg1[32+MAXLEN];//MAXLEN=32,即最多一次可签名32byte的明文消息
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
//将64byte的字符串转换成32byte	
	cinstr(mip, p, cfig->p);
	cinstr(mip, a, cfig->a);
	cinstr(mip, b, cfig->b);
	cinstr(mip, n, cfig->n);
	cinstr(mip, x, cfig->x);
	cinstr(mip, y, cfig->y);
	
	big_to_bytes(mip, 32, a, (char *)aa, TRUE);
	big_to_bytes(mip, 32, b, (char *)bb, TRUE);
	big_to_bytes(mip, 32, x, (char *)xx, TRUE);//g点的x值
	big_to_bytes(mip, 32, y, (char *)yy, TRUE);

//计算ZA
	memcpy(bufza,idlen,2);
	memcpy(bufza+2,id,IDLEN);
	memcpy(bufza+2+IDLEN,aa,32);
	memcpy(bufza+2+IDLEN+32,bb,32);
	memcpy(bufza+2+IDLEN+64,xx,32);
	memcpy(bufza+2+IDLEN+96,yy,32);
	memcpy(bufza+2+IDLEN+128,wx,32);
	memcpy(bufza+2+IDLEN+160,wy,32);
	
	SM3Calc(bufza,192+IDLEN+2, za);
//初始化椭圆曲线
	ecurve_init(mip, a, b, p, MR_PROJECTIVE);

	char mem1[MR_ECP_RESERVE(1)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(1));
	
    g = epoint_init_mem(mip, mem1, 0);
	epoint_set(mip, x, y, 0, g);//设置G点
//A2:计算e=H(ZA||M)	
	memcpy(msg1,za,32);
	memcpy(msg1+32,msg,msglen);
	SM3Calc(msg1, 32+msglen, ee);
	bytes_to_big(mip, 32, (char *)ee, e);//将字符串转换为整数
//A3	
A3:	
	do
	{
		irand(mip, SEED_CONST+TIM_GetCounter(TIM3));
		bigrand(mip, n, k);
	} while (size(k)==0);//生成随机大数k

//A4:计算(x1,y1)=k[G]
	ecurve_mult(mip, k, g, g);//g=[k]g
	epoint_get(mip, g, x1, y1);//将g的坐标取出赋给x1,y1

//A5:计算r=(e+x1)mod n 
	add(mip,e,x1,r1);//r=e+x1
	divide (mip,r1,n,n);//r=r (mod n)=(e+x1)mod n
	add(mip,r1,k,rk);
	if((size(r1)==0)||(!mr_compare(rk,n)))
		goto A3;
	big_to_bytes(mip, 32, r1, (char *)r, TRUE);
//A6:计算s=((1+dB)^(-1)*(k-r*dB))mod n

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
* @brief  SM2验签
* @param  msg：密文
* @param  msglen：密文长度
* @param  id：用户Id
* @param  wx：用户公钥x坐标
* @param  wy：用户公钥y坐标
* @param  r,s：签名
* @retval 0:验证通过,1:验证失败 
*/
int sm2_vrisign(unsigned char *msg,int msglen,unsigned char *id,unsigned char *wx,unsigned char *wy,\
            unsigned char *r,unsigned char *s)
{
	struct FPECC *cfig = &Ecc256;
	big a,b,p,n,x,y;
	big rr,ss,e,x1,y1,R,t,px,py;
	epoint *g, *w;
	unsigned char bufza[192+IDLEN+2];//假设id长度为4byte
	unsigned char idlen[2]={0x00,0x90};
	unsigned char aa[32];
	unsigned char bb[32];
	unsigned char xx[32];
	unsigned char yy[32];
	unsigned char za[32];
	unsigned char ee[32];
	unsigned char msg1[32+MAXLEN];//MAXLEN=128=64+32+32,即最多一次可签名256bit的明文消息
	
	miracl instance;
    miracl *mip = &instance;
	
	mip = mirsys(mip, 20, 0);   //初始化大数系统
	mip->IOBASE = 16;
	
	char mem[MR_BIG_RESERVE(15)];
    memset(mem, 0, MR_BIG_RESERVE(15));
	
	p= mirvar_mem(mip, mem, 0);//初始化大数变量
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
	
	cinstr(mip, p,cfig->p);//将字符串转换为整型
	cinstr(mip, a,cfig->a);
	cinstr(mip, b,cfig->b);
	cinstr(mip, n,cfig->n);
	cinstr(mip, x,cfig->x);
	cinstr(mip, y,cfig->y);
	
	big_to_bytes(mip, 32, a, (char *)aa, TRUE);
	big_to_bytes(mip, 32, b, (char *)bb, TRUE);
	big_to_bytes(mip, 32, x, (char *)xx, TRUE);//g点的x值
	big_to_bytes(mip, 32, y, (char *)yy, TRUE);
	
//B1,B2：验证r',s'是否属于[1,n-1]
	bytes_to_big(mip, 32, (char *)r, rr);	
	if((size(rr)<1)||!(mr_compare(n,rr)))
		goto verify_fail;
	bytes_to_big(mip, 32, (char *)s, ss);	
	if((size(ss)<1)||!(mr_compare(n,ss)))
		goto verify_fail;

//计算ZA
	memcpy(bufza,idlen,2);
	memcpy(bufza+2,id,IDLEN);
	memcpy(bufza+2+IDLEN,aa,32);
	memcpy(bufza+2+IDLEN+32,bb,32);
	memcpy(bufza+2+IDLEN+64,xx,32);
	memcpy(bufza+2+IDLEN+96,yy,32);
	memcpy(bufza+2+IDLEN+128,wx,32);
	memcpy(bufza+2+IDLEN+160,wy,32);
	
	SM3Calc(bufza,192+IDLEN+2, za);
	
//初始化椭圆曲线	
	ecurve_init(mip, a,b,p,MR_PROJECTIVE);
	char mem1[MR_ECP_RESERVE(2)]; 
	memset(mem1 ,0, MR_ECP_RESERVE(2));	
    g = epoint_init_mem(mip, mem1, 0);
	w = epoint_init_mem(mip, mem1, 1);
	epoint_set(mip, x, y, 0, g);//设置G点
	bytes_to_big(mip, 32,(char *)wx,px);//将公钥值传入px和py
	bytes_to_big(mip, 32,(char *)wy,py);
	epoint_set(mip, px,py,0,w);//设置公钥P点
	
//B3、B4:计算e'=H(ZA||M')	
	memcpy(msg1,za,32);
	memcpy(msg1+32,msg,msglen);
	SM3Calc(msg1, 32+msglen, ee);
	bytes_to_big(mip, 32, (char *)ee, e);//将字符串转换为整数
//B5:计算t=(r'+s') mod n,若t=0则验证不通过
	add(mip,rr,ss,t);//t=r'+s'
	divide(mip,t,n,n);//t=t (mod n)=(r'+s')mod n	
	if(size(t)==0)
		goto verify_fail;
//B6:计算(x1',y1')=[s']G+[t]P
	ecurve_mult(mip, ss, g, g);//G=[s']G
	ecurve_mult(mip,t,w,w);//P=[t]P
	ecurve_add(mip,g, w);
	epoint_get(mip,w, x1, y1);

	
//B7:计算R=(e'+x1')	mod n,验证R=r'是否成立
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
* @brief  SM2加解密测试
* @param  tx：        输入的明文结构体
* @retval 0：正常返回 
*/
int sm2_encrypt_test(TEXT *tx)
{	
	printf("\r\n******************* SM2 *******************\r\n");
	unsigned char dB[32];   //存放私钥
	unsigned char xB[32];   //存放公钥pb（x，y）
	unsigned char yB[32];
	unsigned char msgsigned[320];//256+64
	unsigned char etx[256];
	unsigned char mtx[256];
	unsigned char id[IDLEN]={0x41,0x4C,0x49,0x43,0x45,0x31,0x32,0x33,0x40,0x59,0x41,0x48,0x4F,0x4F,0x2E,0x43,0x4F,0x4D};

	int wxlen, wylen, privkeylen,ret,etxlen;

    
	sm2_keygen(xB, &wxlen, yB, &wylen, dB, &privkeylen);
	printf("\r\nPrivate key： ");
	PrintBuf(dB, 32);
	printf("Public key x： ");
	PrintBuf(xB, 32);
	printf("Public key y： ");
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
	unsigned char dB[32];   //存放私钥
	unsigned char xB[32];   //存放公钥pb（x，y）
	unsigned char yB[32];
	unsigned char etx[256];
	unsigned char mtx[256];
	int wxlen, wylen, privkeylen,ret,etxlen;
  
	sm2_keygen(xB, &wxlen, yB, &wylen, dB, &privkeylen);
	printf("\r\nPrivate key： ");
	PrintBuf(dB, 32);
	printf("Public key x： ");
	PrintBuf(xB, 32);
	printf("Public key y： ");
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
