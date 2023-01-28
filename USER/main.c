#include "delay.h"
#include "key.h"
#include "sys.h"
#include "usart.h"	 
#include "w25qxx.h"	 
#include "sm2.h"
 
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

 int main(void)
 {	 
	u8 key;
	u32 FLASH_SIZE; 
    u16 id = 0;
	TEXT tx;
	TEXT datatemp;
     
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
					tx.len=USART_RX_STA&0x3fff;//得到此次接收到的数据长度
					tx.content=USART_RX_BUF;	
					PrintBuf(tx.content, tx.len);							
					USART_RX_STA=0;
					break;
				}
			}
			  
			W25QXX_Write((u8*)tx.content,0,tx.len);			//从倒数第100个地址处开始,写入SIZE长度的数据
			printf("W25Q128 Write Finished!\r\n");	//提示传送完成
		}
		if(key==KEY0_PRES)	//KEY0按下,读取字符串并显示
		{
 			printf("Start Read W25Q128.... \r\n");
			W25QXX_Read(datatemp.content,0,tx.len);					//从倒数第100个地址处开始,读出SIZE个字节			
			printf("The Data Readed Is:  ");	//提示传送完成
			PrintBuf(datatemp.content,tx.len);
		}	   
	}
}


