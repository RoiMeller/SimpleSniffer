/*
 * TCP_UDP.h
 *
 *  Created on: Nov 23, 2014
 *      Author: root
 */

#ifndef TCP_UDP_H_
#define TCP_UDP_H_

# include <error.h>
# include <errno.h>


/* GLOBAL VARIABLES */

uint  udp_tcp_sport_is_filter;
uchar udp_tcp_sport_not = 0;

uint  udp_tcp_dport_is_filter;
uchar udp_tcp_dport_not = 0;

/* STRUCTS */

struct tcpudp_port_header {
    uint srcPort: 16;
    uint dstPort: 16;
};

typedef struct _udpHdr {
    uint srcPort: 16;
    uint dstPort: 16;
    uint udpPktLen: 16;
    uint cksum: 16;
}udpHdr;

typedef union _optsUnion{
    struct{
	#ifdef __LITTLE_ENDIAN__
        uint fin:1;
        uint syn:1;
        uint rst:1;
        uint psh:1;
        uint ack:1;
        uint urg:1;
        uint res:2;
	#elif defined __BIG_ENDIAN__
        uint res:2;
        uint urg:1;
        uint ack:1;
        uint psh:1;
        uint rst:1;
        uint syn:1;
        uint fin:1;
	#else
		# error "Set Big/Little Endianness"
#endif
    }flags;
    uchar options;
}opts;

typedef struct _tcpHdr
{
    uint srcPort:16;
    uint dstPort:16;
    uint seqNum;
    uint ackNum;
#ifdef __LITTLE_ENDIAN__
    uint  reserved   : 4; // 4 bits
    uint  dataOffset : 4; // 4 bits
#elif defined __BIG_ENDIAN__
    uint  dataOffset : 4; // 4 bits
    uint  reserved   : 4; // 4 bits
#else
	#error "Set Big/Little endianness"
#endif
    opts options;
    uint window: 16;
    uint cksum: 16;
    uint urgp: 16;
} tcpHdr;



/*the tcp pseudo header*/
struct tcp_pseudo {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char zero; // need to check why we use it!!!
    unsigned char proto;
    unsigned short length;
} pseudohead;


long checksum(unsigned short *addr, unsigned int count);
long get_udp_checksum(struct ip_packet * myip, udpHdr * myudp);
long get_tcp_checksum(struct ip_packet * myip, tcpHdr * mytcp);
int udptcp_sport_cmp(struct ip_packet *ip, uint filter_port);
int udptcp_dport_cmp(struct ip_packet *ip, uint filter_port);








#endif /* TCP_UDP_H_ */
