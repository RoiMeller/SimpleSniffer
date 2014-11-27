# include <stdio.h>				// For standard things
# include <stdlib.h>			// malloc / EXIT_SUCCESS = 0, EXIT_FAILURE = 
# include <string.h>			// strlen
# include <netinet/in.h>		// Internet Protocol family

# include "GOhdr.h"
# include "IP.h"
# include "TCP_UDP.h"


/* used to ensure the integrity of data portions for data transmission */
long checksum(unsigned short *addr, unsigned int count) {

	/* Compute Internet Checksum for "count" bytes at the beginning location-"addr". */
    register long sum = 0;

    while( count > 1 ) {
        /*  This is the inner loop */
        sum += * addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 ){
        sum += * (unsigned char *) addr;
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

long get_udp_checksum(struct ip_packet * myip, udpHdr * myudp) {

	long res;
	int totaludp_len = 0;
	unsigned short * udp = NULL;
    unsigned short total_len = ntohs(myip->packet_len);

    int udpdatalen = total_len - sizeof(udpHdr) - (myip->header_len*4);

    pseudohead.src_addr=myip->ip_src.addr;
    pseudohead.dst_addr=myip->ip_dst.addr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(udpHdr) + udpdatalen );

    totaludp_len = sizeof(struct tcp_pseudo) + sizeof(udpHdr) + udpdatalen;

	udp = (unsigned short*)malloc(totaludp_len);

	if(udp == NULL){
		perror("Allocation faild");
		return EXIT_failure;
	}

    memcpy((unsigned char *)udp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)udp+sizeof(struct tcp_pseudo),(unsigned char *)myudp,sizeof(udpHdr));
    memcpy((unsigned char *)udp+sizeof(struct tcp_pseudo)+sizeof(udpHdr), (unsigned char *)myip+(myip->header_len*4)+(sizeof(udpHdr)), udpdatalen);

    res = checksum(udp,totaludp_len);
    free(udp);
    return res;
}

long get_tcp_checksum(struct ip_packet * myip, tcpHdr * mytcp) {

	int totaltcp_len = 0;
	long res = 0;
	unsigned short * tcp = NULL;
	unsigned short total_len = ntohs(myip->packet_len);

    int tcpopt_len = mytcp->dataOffset*4 - 20;
    int tcpdatalen = total_len - (mytcp->dataOffset*4) - (myip->header_len*4);

    pseudohead.src_addr=myip->ip_src.addr;
    pseudohead.dst_addr=myip->ip_dst.addr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(tcpHdr) + tcpopt_len + tcpdatalen);

    totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(tcpHdr) + tcpopt_len + tcpdatalen;

    tcp = (unsigned short*)malloc(totaltcp_len);

    if(tcp == NULL){
		perror("Allocation faild");
		return EXIT_failure;
    }

    memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)mytcp,sizeof(tcpHdr));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(tcpHdr), (unsigned char *)myip+(myip->header_len*4)+(sizeof(tcpHdr)), tcpopt_len);
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(tcpHdr)+tcpopt_len, (unsigned char *)mytcp+(mytcp->dataOffset*4), tcpdatalen);

    res = checksum(tcp,totaltcp_len);
    free(tcp);
    return res;
}

int udptcp_sport_cmp(struct ip_packet *ip, uint filter_port){
    uchar *buffer = (void *)ip;
    struct tcpudp_port_header *hdr = (void *)(buffer + (ip->header_len*4));

    if((ip->protocol != IPPROTO_TCP) && (ip->protocol != IPPROTO_UDP)){
        return EXIT_success;
    }

    return (ntohs(hdr->srcPort) == filter_port) ? 0 : -1;
}

int udptcp_dport_cmp(struct ip_packet *ip, uint filter_port){
    uchar *buffer = (void *)ip;
    struct tcpudp_port_header *hdr = (void *)(buffer + (ip->header_len*4));

    if((ip->protocol != IPPROTO_TCP) && (ip->protocol != IPPROTO_UDP)){
        return EXIT_success;
    }

    return (ntohs(hdr->dstPort) == filter_port) ? 0 : -1;
}
