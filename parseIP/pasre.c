/*
 ============================================================================
 Name        : pasre.c
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

typedef struct ip_hdr{
	unsigned char version:4 ;
	unsigned char IpHL:4;
	unsigned char Tos ;
	unsigned short int Total_len;
	unsigned short int ID;
	unsigned short int flag_offset;
	unsigned char Ttl;
	unsigned char protocol;
	unsigned short int chksum;
	unsigned int Sraddr;
	unsigned int Daddr;

}ip_hdr;



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
	 printf(" IP Time To Live             : %d\n",(unsigned int)ip_header->Ttl);
	 printf(" IP Protocol                 : %d\n",(unsigned int)ip_header->protocol);
	 printf(" IP CheckSum                 : %d\n",ntohs(ip_header->chksum));
	 printf(" IP Server IP                : %s\n",inet_ntoa(source.sin_addr));
	 printf(" IP Time To Live             : %s\n",inet_ntoa(dest.sin_addr));


 }












