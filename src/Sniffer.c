/*
 ============================================================================
 Name        : Sniffer.c
 Description : Command Line Packet sniffer
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {

	int i, recv_length, sockfd;
	u_char buffer[1000];

	if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	fprintf("In socket ERROR");
	exit(0);

	printf("welcome to RAW sniffer\n sniffing...\n");

	do {
		recv_length = recv(sockfd, buffer, 8000, 0);
		printf("\n\ Got a %d byte packet\n", recv_length);
		dump(buffer, recv_length);
	}

	while(1);

	return EXIT_SUCCESS;
}
