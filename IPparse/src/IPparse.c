/*
 ============================================================================
 Name        : IPpasre.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include <ifaddrs.h>


typedef struct ip_hdr{
	unsigned char version:4 ;/*holds 4 bits of version */
	unsigned char IpHL:4;/*holds 4 bits of IP Header Length */
	unsigned char Tos ; /*holds 8 bits of Type of system */
	unsigned short int Total_len; /*holds 16 bits of Total length */
	unsigned short int ID; /*holds 16 bits of Identification */
	unsigned char flags:3; /*holds 3 bits of flags */
	unsigned short int offset:13;/* 13 bits of fragment offset */
	unsigned char Ttl;/*holds 8 bits of Time to live */
	unsigned char protocol;/*holds 8 bits of protocol */
	unsigned short int chksum;/*holds 16 bits of checksum */
	unsigned int Sraddr;/*holds 32 bits of server address */
	unsigned int Daddr;/*holds 32 bits of destination address */

}ip_hdr;


void print_device_list(struct ifaddrs *dev_list){
	if (dev_list == NULL){
		printf("End List\n");
		return;
	}
	printf("%s \n",dev_list->ifa_name);
	print_device_list(dev_list->ifa_next);

}






/*function print_ip_header() - unsigned char *buffer holds the ip header
 * 							   integer size holds the buffer size
 * 							   the function is printing the header in is details
 * 							   non - return function  */
 void print_ip_header(unsigned char *buffer,int size){
	 struct ip_hdr *ip_header = NULL;
	 struct sockaddr_in source,dest;
	 ip_header = (struct ip_hdr *)buffer;

	 memset(&source,0,sizeof(source));
	 memset(&dest,0,sizeof(dest));
	 source.sin_addr.s_addr = ip_header->Sraddr;
	 dest.sin_addr.s_addr = ip_header->Daddr;

	 printf("\n");
	 printf(" IP HEADER \n");
	 printf(" IP Version                  : %d\n",(unsigned int)ip_header->version);
	 printf(" IP Header Len in Bytes      : %d\n",(unsigned int)ip_header->IpHL);
	 printf(" IP Type Of Serves           : %d\n",(unsigned int)ip_header->Tos);
	 printf(" IP Total Length in Bytes    : %d\n",ntohs(ip_header->Total_len));
	 printf(" IP Identification           : %d\n",ntohs(ip_header->ID));
	 printf(" IP flags                    : %d\n",(unsigned int)ip_header->flags);
	 printf(" IP Offset                   : %d\n",(unsigned int)ip_header->offset);
	 printf(" IP Time To Live             : %d\n",(unsigned int)ip_header->Ttl);
	 printf(" IP Protocol                 : %d\n",(unsigned int)ip_header->protocol);
	 printf(" IP CheckSum                 : %d\n",ntohs(ip_header->chksum));
	 printf(" IP Server IP                : %s\n",inet_ntoa(source.sin_addr));
	 printf(" IP Time To Live             : %s\n",inet_ntoa(dest.sin_addr));


 }





 void print_data(unsigned char *buffer , int size){
 	int i = 0;
 	int j = 0;

 	for(i = 0 ; i < size ; i++){
 		printf("%02x ",buffer[i]);
 		if (i%16 == 0 && i != 0){
 			printf("      ");
 			for(j = (i-16);j<i ; j++){
 				if (buffer[j]>=32 && buffer[j]<=128){
 					printf("%c",(unsigned char)buffer[j]);
 				}else{
 					printf(".");
 				}
 			}
 			printf("\n");
 		}
 	}
 	if( i==size-1)  //print the last spaces
 	{
 		for(j=0;j<15-i%16;j++){
 			printf("   "); //extra spaces
 		}

 		printf("         ");

 		for(j=i-i%16 ; j<=i ; j++)
 		{
 			if(buffer[j]>=32 && buffer[j]<=128){
 				printf("%c",(unsigned char)buffer[j]);
 			}else{
 				printf(".");
 			}
 		}
 		printf("\n");

 	}
 }












 int main(void){




return(1);
}




