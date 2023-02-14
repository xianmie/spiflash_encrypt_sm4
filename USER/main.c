#include "delay.h"
#include "key.h"
#include "sys.h"
#include "usart.h"	 
#include "w25qxx.h"	 
#include "sm2.h"
#include "sm4.h" 
/************************************************
 ALIENTEK战舰STM32开发板实验24
 SPI 实验   
 技术支持：www.openedv.com
 淘宝店铺：http://eboard.taobao.com 
 关注微信公众平台微信号："正点原子"，免费获取STM32资料。
 广州市星翼电子科技有限公司  
 作者：正点原子 @ALIENTEK
************************************************/

 				 	
//要写入到W25Q64的字符串数组
#define ONE_LEN1 4096
#define ONE_LEN2 16
#define CBC 0
 int main(void)
 {	 
	u8 key;
	u32 FLASH_SIZE; 
    u16 id = 0;
	u8 flagAddr;
	TEXT plaintemp;//明文

	unsigned char sm4key[16];
	unsigned char cipher[ONE_LEN1];
	unsigned char datatemp[ONE_LEN2+16];
	unsigned char outplain[ONE_LEN2];
     
	delay_init();	    	 //延时函数初始化	  
    NVIC_PriorityGroupConfig(NVIC_PriorityGroup_2);//设置中断优先级分组为组2：2位抢占优先级，2位响应优先级
	uart_init(115200);	 	//串口初始化为115200
	KEY_Init();				//按键初始化		 	 	
	W25QXX_Init();			//W25QXX初始化

	while(1)
	{
		id = W25QXX_ReadID();
		if (id == W25Q128 || id == NM25Q128)
			break;
		printf("W25Q128 Check Failed!\r\n");
		delay_ms(500);
		printf("Please Check!        \r\n");
		delay_ms(500);
	}
	printf("W25Q128 Ready!Press KEY1 to write and KEY0 to read.\r\n");    
	FLASH_SIZE=128*1024*1024;	//FLASH 大小为16M字节
	
	while(1)
	{
		key=KEY_Scan(0);
		if(key==KEY1_PRES)	//KEY1按下,写入W25QXX
		{
 			printf("Start Write W25Q128....\r\n"); 
			printf("please input key to store:");
			while(1)
			{
				if(USART_RX_STA&0x8000)
				{
					plaintemp.len=USART_RX_STA&0x3fff;//得到此次接收到的数据长度
					plaintemp.content=USART_RX_BUF;
					PrintBuf(plaintemp.content, plaintemp.len);							
					USART_RX_STA=0;
					break;
				}
			}

			sm4_encrypt_ecb(sm4key,plaintemp.content,cipher,ONE_LEN1);
//			printf("The Data encrypted Is:  ");	
//			PrintBuf(cipher,ONE_LEN);			
			W25QXX_Write((u8*)cipher,0,ONE_LEN1);	//从第0个地址处开始,写入ONE_LEN长度的数据
			printf("W25Q128 Write Finished!\r\n");	//提示传送完成
		}
		if(key==KEY0_PRES)	//KEY0按下,读取字符串并显示
		{
 			printf("Start Read W25Q128.... \r\n");
			int readAdrr=16;
			if(readAdrr!=0&&CBC)
			{
				W25QXX_Read(datatemp,readAdrr-16,ONE_LEN2+16);	//从第0个地址处开始,读出ONE_LEN个字节			
				flagAddr=1;
			}
			else
			{			
				W25QXX_Read(datatemp,readAdrr,ONE_LEN2);
				flagAddr=0;
			}
//			printf("The Data Readed Is:  ");	//提示传送完成
//			PrintBuf(datatemp,ONE_LEN);
			sm4_decrypt_ecb(sm4key,datatemp,outplain,ONE_LEN2);
			printf("The Data After Decrypt Is:  ");	
			PrintBuf(outplain,ONE_LEN2);			
		}	   
	}
}
