/*
 ============================================================================
 Name        : Tcp.c
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

#include <endian.h>
#include <linux/socket.h>
#include <sys/types.h>

#include <unistd.h>
#include <string.h>

/* Define tcp_seq */
#define tcp_seq u_int32_t

struct tcp_hdr { /* TCP header */
	u_short th_sport; /* Source port */
	u_short th_dport; /* Destination port */

	tcp_seq th_seq; /* Sequence number */
	tcp_seq th_ack; /* Acknowledgment number */

/*
 *  TCP use this for integer fields (e.g. port numbers)
 *  Functions such as htons and ntohs can be used to do conversion
 *  We use if/endif to determinate what the Network byte order
 */

#if BYTE_ORDER == LITTLE_ENDIAN
	u_int th_x2:4, /* (Unused) */
	th_off:4; /* Data offset */
#endif

#if BYTE_ORDER == BIG_ENDIAN
	u_int th_off:4, /* Data offset */
	th_x2:4; /* (Unused) */
#endif

	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#ifndef TH_FLAGS
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#endif

	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};

void print_tcp_packet(const u_char * packet_data)
{

	struct tcp_hdr *th = (struct tcp_hdr *) packet_data;

	printf("\n*********************** TCP Packet *************************\n");

    printf("\n");
    printf("TCP Header\n");
    printf("   | Source Port			: %u\n",ntohs(th->th_sport));
    printf("   | Destination Port		: %u\n",ntohs(th->th_dport));
    printf("   | Sequence Number		: %u\n",ntohl(th->th_seq));
    printf("   | Acknowledge Number		: %u\n",ntohl(th->th_ack));
    printf("   | Header Length			: %d DWORDS or %d BYTES\n" ,(unsigned int)th->th_x2,(unsigned int)th->th_off);
    printf("   | Flags					: %c\n",(u_char)th->th_flags);
    printf("   | Window					: %d\n",ntohs(th->th_win));
    printf("   | Checksum				: %d\n",ntohs(th->th_sum));
    printf("   | Urgent Pointer			: %d\n",th->th_urp);
    printf("\n");

    printf("\n==============================================================");
}
