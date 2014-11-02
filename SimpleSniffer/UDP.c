/*
 ============================================================================
 Name        : UDP.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct udp_hdr {

	unsigned short Src_Port;
	unsigned short Dst_Port;
	unsigned short Length;
	unsigned short CheckSum;

};

void udp_dump(const u_char * packet_data){

	struct udp_hdr *udp = (struct udp_hdr *)packet_data;

	printf("\n*********************** UDP Packet *************************\n");
	printf("\n");
	printf("TCP Header\n");
	printf("   | Source Port			: %u\n",ntohs(udp->Src_Port));
	printf("   | Destination Port		: %u\n",ntohs(udp->Dst_Port));
	printf("   | Length          		: %u\n",ntohs(udp->Length));
	printf("   | CheckSum				: %u\n",ntohs(udp->CheckSum));
	printf("\n");
	printf("\n==============================================================");


}
