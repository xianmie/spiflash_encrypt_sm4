#include "delay.h"
#include "key.h"
#include "sys.h"
#include "usart.h"	 
#include "w25qxx.h"	 
#include "sm2.h"
#include "sm4.h" 
/************************************************
 ALIENTEKս��STM32������ʵ��24
 SPI ʵ��   
 ����֧�֣�www.openedv.com
 �Ա����̣�http://eboard.taobao.com 
 ��ע΢�Ź���ƽ̨΢�źţ�"����ԭ��"����ѻ�ȡSTM32���ϡ�
 ������������ӿƼ����޹�˾  
 ���ߣ�����ԭ�� @ALIENTEK
************************************************/

 				 	
//Ҫд�뵽W25Q64���ַ�������
#define ONE_LEN1 4096
#define ONE_LEN2 16
#define CBC 0
 int main(void)
 {	 
	u8 key;
	u32 FLASH_SIZE; 
    u16 id = 0;
	u8 flagAddr;
	TEXT plaintemp;//����

	unsigned char sm4key[16];
	unsigned char cipher[ONE_LEN1];
	unsigned char datatemp[ONE_LEN2+16];
	unsigned char outplain[ONE_LEN2];
     
	delay_init();	    	 //��ʱ������ʼ��	  
    NVIC_PriorityGroupConfig(NVIC_PriorityGroup_2);//�����ж����ȼ�����Ϊ��2��2λ��ռ���ȼ���2λ��Ӧ���ȼ�
	uart_init(115200);	 	//���ڳ�ʼ��Ϊ115200
	KEY_Init();				//������ʼ��		 	 	
	W25QXX_Init();			//W25QXX��ʼ��

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
	FLASH_SIZE=128*1024*1024;	//FLASH ��СΪ16M�ֽ�
	
	while(1)
	{
		key=KEY_Scan(0);
		if(key==KEY1_PRES)	//KEY1����,д��W25QXX
		{
 			printf("Start Write W25Q128....\r\n"); 
			printf("please input key to store:");
			while(1)
			{
				if(USART_RX_STA&0x8000)
				{
					plaintemp.len=USART_RX_STA&0x3fff;//�õ��˴ν��յ������ݳ���
					plaintemp.content=USART_RX_BUF;
					PrintBuf(plaintemp.content, plaintemp.len);							
					USART_RX_STA=0;
					break;
				}
			}

			sm4_encrypt_ecb(sm4key,plaintemp.content,cipher,ONE_LEN1);
//			printf("The Data encrypted Is:  ");	
//			PrintBuf(cipher,ONE_LEN);			
			W25QXX_Write((u8*)cipher,0,ONE_LEN1);	//�ӵ�0����ַ����ʼ,д��ONE_LEN���ȵ�����
			printf("W25Q128 Write Finished!\r\n");	//��ʾ�������
		}
		if(key==KEY0_PRES)	//KEY0����,��ȡ�ַ�������ʾ
		{
 			printf("Start Read W25Q128.... \r\n");
			int readAdrr=16;
			if(readAdrr!=0&&CBC)
			{
				W25QXX_Read(datatemp,readAdrr-16,ONE_LEN2+16);	//�ӵ�0����ַ����ʼ,����ONE_LEN���ֽ�			
				flagAddr=1;
			}
			else
			{			
				W25QXX_Read(datatemp,readAdrr,ONE_LEN2);
				flagAddr=0;
			}
//			printf("The Data Readed Is:  ");	//��ʾ�������
//			PrintBuf(datatemp,ONE_LEN);
			sm4_decrypt_ecb(sm4key,datatemp,outplain,ONE_LEN2);
			printf("The Data After Decrypt Is:  ");	
			PrintBuf(outplain,ONE_LEN2);			
		}	   
	}
}
