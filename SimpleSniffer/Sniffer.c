#if defined(linux) // This program is Linux-specific !

/*
 ================
  Packet Sniffer
 ================
*/

/* INCLUDES */

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

/* Function & Global Declaration */

#define ERROR_PRINT perror

#define INCREMENT_CAP   14
#define SOCK_FAM_TYPE   PF_PACKET /* packet interface on device level */

#define SOCK_PROTO_TYPE htons(ETH_P_IP) // Host byte order to network byte order

#define IP_SIZE  4
#define ETH_SIZE 6 /* Ethernet addresses are 6 bytes */

typedef enum { eETH_ADDR, eIP_ADDR } EAddress; // PrintAddr()
typedef unsigned int uint;
typedef unsigned char uchar;

int debug = 0;
int addr = 0;

/*
 ============================================================================
 This structure defines the fields within the IP frame. Since this program
 gets the lowest-level packet, fragmented packets are not reassembled.
 The first few fields contain the MAC addresses of the source and destination.
 Note that this structure is set for little-endian format.

 So I cheated and stole someone else's IP header... sue me :)
 ============================================================================
*/
struct ip_packet {
    uint header_len:4;       /* header length in words in 32bit words */
    uint version:4;          /* 4-bit version */
    uint serve_type:8;       /* how to service packet */
    uint packet_len:16;      /* total size of packet in bytes */
    uint ID:16;              /* fragment ID */
    uint frag_offset:13;     /* to help reassembly */
    uint more_frags:1;       /* flag for "more frags to follow" */
    uint dont_frag:1;        /* flag to permit fragmentation */
    uint __reserved:1;       /* always zero */
    uint time_to_live:8;     /* maximum router hop count */
    uint protocol:8;         /* ICMP, UDP, TCP */
    uint hdr_chksum:16;      /* ones-comp. checksum of header */
    uchar IPv4_src[IP_SIZE]; /* IP address of originator */
    uchar IPv4_dst[IP_SIZE]; /* IP address of destination */
    uchar options[0];        /* up to 40 bytes */
    uchar data[0];           /* message data up to 64KB */
};

void DebugPrint(char *buf){
#ifdef DEBUG
    printf("DEBUG - %s\n", buf);
#endif /* DEBUG */
}

/*
 ============================================================================
 this is going to be crappy! (it was :( )

 Takes an IPv4 dotted-notation address and returns the binary representation.

 param pIpStr A dotted-notation IPv4 address.
 return an IP Address, if one could be looked up. If pIpStr is actually
 IPv6, returns 1. If there was an error, returns -1 or 0.
 ============================================================================
*/
int atoip(const char *pIpStr)
{
    struct addrinfo hints, *servinfo, *p;
    int t = 0;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(pIpStr, NULL, &hints, &servinfo) != 0)
        return 0;

    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET)
        {
            t = ((struct sockaddr_in*)(p->ai_addr))->sin_addr.s_addr;
            break;
        }
        else if(p->ai_family == AF_INET6)
            t = 1; /* for IPv6 we treat it as a "true" value */
        else
            t = 0;
    }
    freeaddrinfo(servinfo);

    return t;
}

void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip){
    int i;
    static struct {
        int len;
        char *fmt;
        char delim;
    } addr_fmt[] = {{ETH_SIZE, "%x", ':'}, {IP_SIZE, "%d", '.'}};

    if(msg != NULL)
        printf("%s", msg);
    for ( i = 0; i < addr_fmt[is_ip].len; i++ ){
        printf(addr_fmt[is_ip].fmt, addr[i]);
        if ( i < addr_fmt[is_ip].len-1 )
            putchar(addr_fmt[is_ip].delim);
    }
}

/* <netinet/in.h> Standard well-defined IP protocols. */
char *GetProtocol(int value){
    switch (value){
    case IPPROTO_IP: return "IP";
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_IGMP: return "IGMP";
#ifndef __WIN32__
    case IPPROTO_PIM: return "PIM";
    case IPPROTO_RSVP: return "RSVP";
    case IPPROTO_GRE: return "GRE";
    case IPPROTO_IPIP: return "IPIP";
    case IPPROTO_EGP: return "EGP";
#endif
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_PUP: return "PUP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_IDP: return "IDP";
    case IPPROTO_IPV6: return "IPV6/4";
    case IPPROTO_RAW: return "RAW";
    default: return "???";
    }
}

int ipcmp(uchar *ipstruct_addr, int addr)
{
    int ipstr_addr = *((int*)ipstruct_addr);
    if(debug)
        printf("[%X]:[%X]\n", addr, ipstr_addr);

    return (addr)?(addr == ipstr_addr) : 1;
}

/*
 ============================================================================
 brief dump the len bytes pointed to by b to file out.

 param b A block of memory
 param len The number of bytes to dump
 param dump An output stream.
 ============================================================================
*/
void dump(void* b, int len, FILE *dump){
    unsigned char *buf = b;
    int i, cnt=0;
    char str[17];
    FILE *out = stdout;
    memset(str, 0, 17);

    if(dump != NULL)
        out = dump;

    for ( i = 0; i < len; i++ ){
        if ( cnt % 16 == 0 ){
            fprintf(out, "  %s\n%04X: ", str, cnt);
            memset(str, 0, 17);
        }
        if ( buf[cnt] < ' '  ||  buf[cnt] >= 127 )
            str[cnt%16] = '.';
        else
            str[cnt%16] = buf[cnt];
        fprintf(out, "%02X ", buf[cnt++]);
    }
    fprintf(out, "  %*s\n\n", 16+(16-len%16)*2, str);
}

void DumpPacket(char *buffer, int len){
    struct ip_packet *ip=(void*)(buffer);

    if(!ipcmp(ip->IPv4_src, addr) &&
       !ipcmp(ip->IPv4_dst, addr))
        return;

    do{
        printf("-------------------------------------------------\n");
        dump(buffer, len, NULL);
//        PrintAddr("Destination EtherID=", ip->hw_header.dst_eth, eETH_ADDR);
//        PrintAddr(", Source EtherID=", ip->hw_header.src_eth, eETH_ADDR);
        printf("\nIPv%d: header-len=%d, type=%d, packet-size=%d, ID=%d\n",
               ip->version, ip->header_len*4, ip->serve_type,
               ntohs(ip->packet_len), ntohs(ip->ID));
        printf("frag=%c, more=%c, offset=%d, TTL=%d, protocol=%s\n",
               (ip->dont_frag? 'N': 'Y'),
               (ip->more_frags? 'N': 'Y'),
               ip->frag_offset,
               ip->time_to_live, GetProtocol(ip->protocol));
        printf("checksum=%d, ", ntohs(ip->hdr_chksum));
        PrintAddr("source=", ip->IPv4_src, eIP_ADDR);
        PrintAddr(", destination=", ip->IPv4_dst, eIP_ADDR);
        printf("\n");
        fflush(stdout);
    }while(0);
}

int main(int argc, char *argv[])
{
    int sd=-1, bytes_read;
    char data[1024];

    struct sockaddr * sa = NULL;
    uint sl;

    if(argc > 1)
    {
        addr = atoip(argv[1]);
        printf("Filtering on addr[%s] [", argv[1]);
        PrintAddr(NULL, (unsigned char *)&addr, eIP_ADDR);
        printf("].\n");
    }

    sd = socket(SOCK_FAM_TYPE, SOCK_RAW, SOCK_PROTO_TYPE);
    if ( sd < 0 )
        perror("Sniff socket");

    do {
        sl = sizeof(struct sockaddr);
        bytes_read = recvfrom(sd, data, sizeof(data), 0, sa, &sl);

        if ( bytes_read > 0 )
        {
            DumpPacket(data+INCREMENT_CAP, bytes_read);
        }
        else if(bytes_read == -1)
        	perror("Sniffer read");

    } while ( bytes_read > 0 );

    return 0;
}

#else

#include <stdio.h>

int main() {
	fprintf(stderr, "This program is Linux-specific\n");
	return 0;
}

#endif

