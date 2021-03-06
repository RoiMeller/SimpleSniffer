	/*
	=====================================================================================
  	Simple CommandLine Packet Sniffer

  	An example program meant as a lightweight tcpdump tool for general
	purpose sniffing and network traffic analysis.

	filtering based on:
	Ethernet mac addresses
	Ethernet types
	Ethernet vlan tags
	IP addresses
	IP protocol
	IP TOS byte
	TCP/UDP ports
	Arbitrary 8-bit, 16-bit, and 32-bit fields at offsets
	Arbitrary 32-bit mask at offset
	Negative versions of the above
	Interface restricted captures
	PCAP file output
	PCAP file input
	Dumping selected packets on an interface

	Simple CL Packet Sniffer has the ability to take an input as either a pcap file,
	or a local interface, and output to one or both of a pcap file and an interface.

  	the format frame: 8 bytes (64 bits)

  	References:
  	classic PCap: http://wiki.wireshark.org/Development/LibpcapFileFormat
	=====================================================================================
	 */

/* INCLUDES */

# include <stdio.h>				// For standard things
# include <stdint.h>			// Declare sets of integer types having specified widths, and shall define corresponding sets of macros.
# include <sys/param.h>			// Old-style Unix parameters and limits
# include <sys/socket.h>		// Declarations of socket constants, types, and functions
# include <arpa/inet.h>			// uint32_t and uint16_t
# include <net/ethernet.h>		// For ether_header
# include <errno.h>				// Defines macros for reporting and retrieving error conditions
# include <sys/types.h>			// Various data types
# include <stdlib.h>			// malloc / EXIT_SUCCESS = 0, EXIT_FAILURE = 1
# include <string.h>			// strlen
# include <netinet/in.h>		// Internet Protocol family
# include <netinet/tcp.h>		// Provides declarations for tcp header
# include <netinet/ip.h>		// Provides declarations for ip header
# include <unistd.h>			// provides access to the POSIX operating system API
# include <fcntl.h>				// File opening, locking and other operations
# include <sys/select.h>		// Define the timeval structure
# include <sys/time.h>			// Time types
# include <features.h>
# include <linux/if.h>			// An implementation of the TCP/IP protocol
# include <linux/if_ether.h>
# include <linux/if_packet.h>
# include <sys/ioctl.h>
# include <sched.h>
# include <signal.h>			// POSIX signals
# include <time.h>
# include <unistd.h>			// Various essential POSIX functions and constants - syscall()
# include <sys/capability.h>
# include <linux/capability.h>	// _LINUX_CAPABILITY_VERSION
# include <sys/syscall.h>		// __NR_capget
# include <netdb.h>				// definitions for network database operations
# include <linux/prctl.h>

/* Function & Global Declaration */

# define ERROR_PRINT perror
# define EXIT_success 0
# define EXIT_failure -1

# ifdef __BYTE_ORDER
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define __LITTLE_ENDIAN__ 1
#  else
#   if __BYTE_ORDER == __BIG_ENDIAN
#    define __BIG_ENDIAN__ 1
#   else
#    error "Unknown byte order"
#   endif
#  endif /* __BYTE_ORDER */
# endif

/* Socket descriptor definition */
# define SOCK_FAM_TYPE PF_PACKET /* packet interface on device level - Every packet */
# define SOCK_PROTO_TYPE htons(ETH_P_ALL) /* Host byte order to network byte order */

# define IP_SIZE  4

/* Ethernet addresses are 6 bytes */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif /*ETH_ALEN*/

/* Defining a parameterized macro */
#define FILTER_CHK_MASK(a,b) (((uint)a&(uint)b) == (uint)b) // The function check for mask value in mask filter
#define FILTER_SET_MASK(a,b) (!FILTER_CHK_MASK(a,b)?a |= b : a) // Return 'b' if 0. 'a' otherwise

/* the following defines are taken from if_ether.h */
# define ETH_P_IP        0x0800          /* Internet Protocol packet     */
# define ETH_P_X25       0x0805          /* CCITT X.25                   */
# define ETH_P_ARP       0x0806          /* Address Resolution packet    */
# define ETH_P_BPQ       0x08FF          /* G8BPQ AX.25 Ethernet Packet  [ NOT AN OFFICIALLY REGISTERED ID ] */
# define ETH_P_IEEEPUP   0x0a00          /* Xerox IEEE802.3 PUP packet */
# define ETH_P_IEEEPUPAT 0x0a01          /* Xerox IEEE802.3 PUP Addr Trans packet */
# define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
# define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
# define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
# define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
# define ETH_P_LAT       0x6004          /* DEC LAT                      */
# define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
# define ETH_P_CUST      0x6006          /* DEC Customer use             */
# define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
# define ETH_P_RARP      0x8035          /* Reverse Addr Res packet      */
# define ETH_P_ATALK     0x809B          /* Appletalk DDP                */
# define ETH_P_AARP      0x80F3          /* Appletalk AARP               */
# define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
# define ETH_P_IPX       0x8137          /* IPX over DIX                 */
# define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */
# define ETH_P_PAUSE     0x8808          /* IEEE Pause frames. See 802.3 31B */
# define ETH_P_SLOW      0x8809          /* Slow Protocol. See 802.3ad 43B */
# define ETH_P_WCCP      0x883E          /* Web-cache coordination protocol
 	 	 	 	 	 	 	 	 	 	 	defined in draft-wilson-wrec-wccp-v2-00.txt */
# define ETH_P_PPP_DISC  0x8863          /* PPPoE discovery messages     */
# define ETH_P_PPP_SES   0x8864          /* PPPoE session messages       */
# define ETH_P_MPLS_UC   0x8847          /* MPLS Unicast traffic         */
# define ETH_P_MPLS_MC   0x8848          /* MPLS Multicast traffic       */
# define ETH_P_ATMMPOA   0x884c          /* MultiProtocol Over ATM       */
# define ETH_P_ATMFATE   0x8884          /* Frame-based ATM Transport
                                          * over Ethernet                                         */
# define ETH_P_AOE       0x88A2          /* ATA over Ethernet            */
# define ETH_P_TIPC      0x88CA          /* TIPC                         */

/* FIlter value reference for mask check and set */
#define ETH_DST_FILTER       0x00000002
#define ETH_SRC_FILTER       0x00000001
#define ETH_TYPE_FILTER      0x00000004
#define ETH_VLAN_FILTER      0x00000008
#define IP_SRC_FILTER        0x00000010
#define IP_DST_FILTER        0x00000020
#define IP_PROTO_FILTER      0x00000040
#define UDP_TCP_SPORT_FILTER 0x00000080
#define UDP_TCP_DPORT_FILTER 0x00000100
#define IP_TOS_BYTE_FILTER   0x00002000

/* Hardware type - arp_hwtype_tostr() */
#define ARP_NETROM 0
#define ARP_ETHER  1
#define ARP_EETHER 2
#define ARP_AX25   3
#define ARP_PRONET 4
#define ARP_CHAOS  5
#define ARP_BLANK  6
#define ARP_ARCNET 7
#define ARP_APPLET 8

/* Operation */
#define ARP_REQUEST 1
#define ARP_REPLY   2

typedef unsigned char uchar;
typedef unsigned int uint;

/*GLOBAL VAR*/

/* Filter mask value for mask check and set */
uint  filter_mask = 0;

/* Declaration */
uchar eth_src_is_mac_filter[ETH_ALEN];
uchar eth_src_not = 0;

uchar eth_dst_is_mac_filter[ETH_ALEN];
uchar eth_dst_not = 0;

uint  eth_type_is_filter;
uchar eth_type_not = 0;

uint  eth_vlan_is_filter;
uchar eth_vlan_not = 0;

uint  need_IP = 0;
uint  ip_src_is_filter;
uchar ip_src_not = 0;

uint  ip_dst_is_filter;
uchar ip_dst_not = 0;

uint  ipproto_is_filter;
uchar ipproto_not = 0;

uint  udp_tcp_sport_is_filter;
uchar udp_tcp_sport_not = 0;

uint  udp_tcp_dport_is_filter;
uchar udp_tcp_dport_not = 0;

uchar ip_tos_byte_filter;
uchar ip_tos_byte_filter_not = 0;

typedef enum { eETH_ADDR, eIP_ADDR } EAddress;

/*
 ============================================================================
 This structure defines the fields within the IP frame. Since this program
 gets the lowest-level packet, fragmented packets are not reassembled.
 The first few fields contain the MAC addresses of the source and destination.
 Note that this structure is set for little-endian format.

 So I cheated and stole someone else's IP header and changed it... sue me :)
 ============================================================================
*/
struct ip_packet {

#ifdef __LITTLE_ENDIAN__
    uint header_len:4;		/* header length in words in 32bit words */
    uint version:4;			/* 4-bit version */
#else	/*!__LITTLE_ENDIAN__ */
    uint version:4;
    uint header_len:4;
#endif	/*!__LITTLE_ENDIAN__ */
    uint serve_type:8;		/* how to service packet */
    uint packet_len:16;		/* total size of packet in bytes */
    uint ID:16;				/* fragment ID */
#ifdef __LITTLE_ENDIAN__
    uint frag_offset:13;	/* to help reassemble */
    uint more_frags:1;		/* flag for "more frags to follow" */
    uint dont_frag:1;		/* flag to permit fragmentation */
    uint __reserved:1;		/* always zero */
#else	/*!__LITTLE_ENDIAN__ */
    uint __reserved:1;
    uint more_frags:1;
    uint dont_frag:1;
    uint frag_offset:13;
#endif	/*!__LITTLE_ENDIAN__ */
    uint time_to_live:8;	/* maximum router hop count */
    uint protocol:8;		/* ICMP, UDP, TCP */
    uint hdr_chksum:16;		/* ones-comp. checksum of header */

    union {
        uint  addr:32;
        uchar IPv4_src[IP_SIZE];	/* IP address of originator */
    } ip_src;

    union {
        uint  addr:32;
        uchar IPv4_dst[IP_SIZE];	/* IP address of destination */
    } ip_dst;

    uchar options[0];	/* up to 40 bytes */
    uchar data[0];		/* message data up to 64KB */
};

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

struct eth_packet {
    uchar dst_mac[ETH_ALEN];
    uchar src_mac[ETH_ALEN];
    uint  eth_type:16;
}eth_packet;

struct eth_8021q_packet {
    uchar dst_mac[ETH_ALEN];
    uchar src_mac[ETH_ALEN];
    uint  eth_type:16;
    uint  priority: 3;
    uint  cfi: 1;
    uint  vlan_id: 12;
    uint  ether_type:16;
};

/*the tcp pseudo header*/
struct tcp_pseudo {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char zero; // need to check why we use it!!!
    unsigned char proto;
    unsigned short length;
} pseudohead;

/* Address Resolution Protocol */
struct arp_packet {
    uint  hw_type    : 16; 	// This field specifies the network protocol type. Example: Ethernet is 1
    uint  proto_type : 16; 	// This field specifies the internetwork protocol for which the ARP request is intended. For IPv4, this has the value 0x0800.
    uchar alen;				// Length (in octets) of a hardware address. Ethernet addresses size is 6.
    uchar proto_alen;		// Length (in octets) of addresses used in the upper layer protocol.
    uint  opcode     : 16; 	// Specifies the operation that the sender is performing: 1 for request, 2 for reply.
};

/* Definitions and descriptions come from: http://wiki.wireshark.org/Development/LibpcapFileFormat */

/* PCAP Global Header - This structure gets written to the start of the file */
typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* Used to detect the file format itself and the byte ordering */
        uint16_t version_major;  /* Major version number - the version number of this file format */
        uint16_t version_minor;  /* Minor version number - the version number of this file format */
        int32_t  thiszone;       /* The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps */
        uint32_t sigfigs;        /* In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0 */
        uint32_t snaplen;        /* The "snapshot length" for the captured packets, in octets */
        uint32_t network;        /* Link-layer header type, specifying the type of headers at the beginning of the packet - http://www.tcpdump.org/linktypes.html */
} pcap_hdr_t;

/* PCAP Record (Packet) Header - This structure precedes each packet */
typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* The date and time when this packet was captured - use time() function from time.h to get this value */
        uint32_t ts_usec;        /* Timestamp microseconds */
        uint32_t incl_len;       /* The number of bytes that packet data actually captured and saved in the file */
        uint32_t orig_len;       /* The length of the packet as it appeared on the network when it was captured */
} pcaprec_hdr_t;

/* PCAP file-format

 0  32-bits - "magic number"
 4  16-bits - "major version"
    16-bits - "minor version"
 8  32-bits - "timezone offset (should be zero)"
12  32-bits - "time stamp accuracy (should be zero)"
16  32-bits - "snap/slice length (maximum packet size)"
20  32-bits - "link layer type"

Magic number:
        a1 b2 c3 d4 = big-endian
        d4 c3 b2 a1 = little-endian

Version:
        2.4 = most common version

Timezone offset, Timestamp accuracy:
        these fields are no longer used

Link-layer type:
        0               BSD loopback devices, except for later OpenBSD
        1               Ethernet, and Linux loopback devices
        6               802.5 Token Ring
        7               ARCnet
        8               SLIP
        9               PPP
        10              FDDI
        100             LLC/SNAP-encapsulated ATM
        101             "raw IP", with no link
        102             BSD/OS SLIP
        103             BSD/OS PPP
        104             Cisco HDLC
        105             802.11
        108             later OpenBSD loopback devices (with the AF_
                        value in network byte order)
        113             special Linux "cooked" capture
        114             LocalTalk
*/
/*
802.11
        11       *  802.11b - 11-mbps
        12       *  802.11d - operation in multiple regulatory domains
        13       *  802.11e - wireless multimedia extensions
        14       *  802.11g - 54-mbps
        15       *  802.11h - power management
        16       *  802.11i - MAC security enhancements
*/

/* Functions */

inline unsigned int endian_swap_32(unsigned int x){ /* PCAP Header BYTEORDER & size */

    x = (x>>24)               |
        ((x<<8) & 0x00ff0000) |
        ((x>>8) & 0x0000ff00) |
        (x<<24)               ;
    return x;
}

inline unsigned short endian_swap_16(unsigned short x){ /* PCAP Header BYTEORDER & size */

    x = (x>>8)|
        (x<<8);
    return x;
}

void print_usage(){
	printf("\n************************************ Simple Command Line packetSniffer ************************************\n");
	printf("| \n");
    printf("| Valid arguments [options]:\n");
    printf("| \n");
    printf("| --output <filename>			To save a .pcap file.\n");
    printf("| --input  <path>or<filename>		Specify a pcap file as the input.\n");
    printf("| --quiet                       	To suppress output.\n");
    printf("| \n");
    printf("| Filter options:\n");
    printf("| \n");
    printf("| --vlan-id               \n");
    printf("| --eth-src   <eth source>		= sniff only from the eth source specified \n");
    printf("| --eth-dst   <eth destination>		= sniff only from the eth destination specified \n");
    printf("| --eth-type  <eth type>		= sniff only from the eth type specified \n");
    printf("| --ip-src    <ip source>		= sniff only from the ip source specified \n");
    printf("| --ip-dst    <ip destination>		= sniff only from the ip destination specified \n");
    printf("| --ip-proto  <ip protocol>		= sniff only from the ip protocol specified \n");
    printf("| --ip-tos    <ip ToS>			= sniff only from the ip ToS specified \n");
    printf("| --ip-sport  <ip source port>		= sniff only from the ip source port specified \n");
    printf("| --ip-dport  <ip destination port>	= sniff only from the ip destination port specified \n");
    printf("| \n");
    printf("| To specify a negative filter use --not, or ! after the filter type.\n");
    printf("| example: --ip-src --not 192.168.1.1\n");
    printf("| \n");
    printf("| --interface\n");
    printf("| \n");
    printf("| Use Ctrl-C to stop capturing at any time.\n");
    printf("| \n");
    printf("************************************************** Usage **************************************************\n");
}

/*
 ===============================================================
 If we were linked with libcap (not related to libpcap) and
 If we started with special privs (ie: suid) then enable for
 ourself the  NET_ADMIN and NET_RAW capabilities and then
 drop our suid privileges.
 ===============================================================
*/
int cap_enable(cap_value_t cap_list[]) {

    int cl_len = 0 ;
    char * name = NULL;
    cap_t caps = cap_init();   /* all capabilities initialized to off */

    uid_t ruid;
    uid_t euid;
    gid_t rgid;
    gid_t egid;

	ruid = getuid();
	euid = geteuid();
	rgid = getgid();
	egid = getegid();

	cl_len = sizeof(cap_list) / sizeof(cap_value_t);

	/*
	======================================================
	Worked thank's to WireShark source code documentation

	If we were started with special privileges, set the
	real and effective group and user IDs to the original
	values of the real and effective group and user IDs.

	(Set the effective UID last - that takes away our
 	rights to set anything else.)
	======================================================
	*/

	/* Real and effective group IDs */
	if (setgid(rgid) == -1) {
		perror("setgid");
		return EXIT_failure;
	}
	if (setegid(rgid) == -1) {
		perror("setegid");
		return EXIT_failure;
	}

	/* Real and effective user IDs */
	if (setuid(ruid) == -1) {
		perror("setuid");
		return EXIT_failure;
	}
	if (seteuid(ruid) == -1) {
		perror("seteuid");
		return EXIT_failure;
	}

    if(cap_set_flag(caps, CAP_PERMITTED,   cl_len, cap_list, CAP_SET) == -1 ){
    	perror("cap_set_flag() set permitted fail return");
    	return EXIT_failure;
    }
    if (cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET) == -1){
    	perror("cap_set_flag() set permitted fail return");
    	return EXIT_failure;
    }
    if(cap_set_flag(caps, CAP_EFFECTIVE, cl_len, cap_list, CAP_SET) == -1){
    	perror("cap_set_flag() set permitted fail return");
    	return EXIT_failure;
    }

    if (cap_set_proc(caps)) {
    	perror("cap_set_proc() fail return");
    	return EXIT_failure;
    }

    name = cap_to_text(caps, NULL);
    printf("After setting: getuid: %d geteuid: %d Capabilities : %s\n", getuid(), geteuid(), name);

    if (cap_free(caps) == -1){
    	perror("CAP_FREE");
    	return EXIT_failure;
    }

    if (cap_free(name) == -1){
    	perror("CAP_FREE");
    	return EXIT_failure;
    }
    return EXIT_success;
}

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
		return EXIT_FAILURE;
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
		return EXIT_FAILURE;
    }

    memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)mytcp,sizeof(tcpHdr));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(tcpHdr), (unsigned char *)myip+(myip->header_len*4)+(sizeof(tcpHdr)), tcpopt_len);
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(tcpHdr)+tcpopt_len, (unsigned char *)mytcp+(mytcp->dataOffset*4), tcpdatalen);

    res = checksum(tcp,totaltcp_len);
    free(tcp);
    return res;
}

/* Get Ethernet address */
void WriteAddr(char *buf, unsigned int buflen, char *msg, unsigned char *addr, EAddress is_ip) {

	int i = 0;
	int l = 0;

	static struct {
        int len;
        char *fmt;
        char delim;
    } addr_fmt[] = {{ETH_ALEN, "%x", ':'}, {IP_SIZE, "%d", '.'}};

    if(msg != NULL){
        l += snprintf(buf, buflen, "%s", msg);
    }

    for ( i = 0; i < addr_fmt[is_ip].len; i++ ){
        if(l < buflen){
        	l += snprintf(buf+l, buflen - l, addr_fmt[is_ip].fmt, addr[i]);
        }
        if ( i < addr_fmt[is_ip].len-1 ){
            if(l < buflen){
            	buf[l++] = addr_fmt[is_ip].delim;
            }
        }
    }
}

/* Print Ethernet address */
void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip) {
	char buf[8192] = {0};

    WriteAddr(buf, 8192, msg, addr, is_ip);
    printf("%s", buf);
}

/* <netinet/in.h> Standard well-defined IP protocols. */
char *GetProtocol(uint value){

	static char protohex[5] = {0};

	switch (value){
		case IPPROTO_IP: return "IP"; 		/* Dummy protocol for TCP.  */
		case IPPROTO_ICMP: return "ICMP"; 	/* Internet Control Message Protocol.  */
		case IPPROTO_IGMP: return "IGMP"; 	/* IPIP tunnels (older KA9Q tunnels use 94).  */
		case IPPROTO_TCP: return "TCP"; 	/* Transmission Control Protocol.  */
		case IPPROTO_PUP: return "PUP";
		case IPPROTO_UDP: return "UDP"; 	/* User Datagram Protocol.  */
		case IPPROTO_IDP: return "IDP";
		case IPPROTO_IPV6: return "IPV 	6/4";
		case IPPROTO_RAW: return "RAW"; 	/* Raw IP packets.  */
	default:
		snprintf(protohex, 5, "0x%02x", value);
		return protohex;
    }
}

/* <linux/if_ether.h> These are the defined Ethernet Protocol ID's. */
char *GetEtherType(int eth_type)
{
    static char protohex[7] = {0};

    switch(eth_type){
    	case ETH_P_IP:    return "IPv4";
    	case ETH_P_8021Q: return "802.1Q";
    	case ETH_P_ARP:   return "ARP";
    	case ETH_P_X25:   return "X.25";
    	case ETH_P_RARP:  return "RARP";
    	case ETH_P_IPV6:  return "IPv6";
    	case ETH_P_TIPC:  return "TIPC";
    default:
        snprintf(protohex, 7, "0x%04x", eth_type);
        return protohex;
    }
}

int eth_contains_ip(struct eth_packet *eth_pkt){ // eth main struct
    if(ntohs(eth_pkt->eth_type) == ETH_P_8021Q){
        return 18;
    }else if (ntohs(eth_pkt->eth_type) == ETH_P_IP){
        return 14;
    }

    return 0;
}

int ipcmp(uchar *ipstruct_addr, int addr){ // Struct & filtering

	int ipstr_addr = *((int*)ipstruct_addr);

    return (addr) ? ((addr == ipstr_addr) ? 1 : 0) : 0;
}

int ethmask_cmp(unsigned char *retr_addr, unsigned char *filter_addr){ // // Struct & filtering
    int i =0 ;

    for(;i<ETH_ALEN;++i){
        if(filter_addr[i] != retr_addr[i]){
            return EXIT_success;
        }
    }
    return EXIT_failure;
}

int ethtype_cmp(uint retr_type, uint filter_type){ // GetEtherType() & filtering
    return (retr_type == filter_type) ? EXIT_success : EXIT_failure;
}

int ethvlan_cmp(struct eth_packet *eth_pkt, uint vlan_tag){
    struct eth_8021q_packet *q_pkt = (void *)(eth_pkt);
    uint retr_id;

    if(!ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_8021Q)){
        return EXIT_success;
    }

    retr_id = q_pkt->vlan_id;

    return (ntohs(retr_id) == vlan_tag) ? EXIT_success : EXIT_failure;
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

/* ARP HW type to string */
char *arp_hwtype_tostr(unsigned short hwtype){

    switch (hwtype){
    case ARP_NETROM:
        return "NetRom";
    case ARP_ETHER:
        return "Ethernet";
    case ARP_EETHER:
        return "ExpEther";
    case ARP_AX25:
        return "AX.25";
    case ARP_PRONET:
        return "ProNet";
    case ARP_CHAOS:
        return "CHAOS";
    case ARP_BLANK:
        return "\"blank\"";
    case ARP_ARCNET:
        return "ARCNET";
    case ARP_APPLET:
        return "APPLETalk";
    default:
        return "unknown";
    }
}

/* internetwork protocol */
char *arp_target_proto(struct arp_packet *arp){
    unsigned char *tgt_proto_start;
    static char buf[80] = {0};

    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP)){
        return "???";
    }

    tgt_proto_start = ((unsigned char *) arp);
    tgt_proto_start += sizeof(struct arp_packet);
    tgt_proto_start += 16;

    WriteAddr(buf, 80, NULL, tgt_proto_start, eIP_ADDR);
    return buf;
}

char *arp_target_hw(struct arp_packet *arp){
    unsigned char *tgt_hw_start;
    static char buf[80] = {0};

    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP)){
        return "???";
    }

    tgt_hw_start = ((unsigned char *) arp);
    tgt_hw_start += sizeof(struct arp_packet);
    tgt_hw_start += 10;

    WriteAddr(buf, 80, NULL, tgt_hw_start, eETH_ADDR);
    return buf;
}

char *arp_sender_proto(struct arp_packet *arp){
    unsigned char *snd_proto_start;
    static char buf[80] = {0};

    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP)){
        return "???";
    }

    snd_proto_start = ((unsigned char *) arp) ;
    snd_proto_start += sizeof(struct arp_packet);
    snd_proto_start += 6;

    WriteAddr(buf, 80, NULL, snd_proto_start, eIP_ADDR);
    return buf;
}

char *arp_sender_hw(struct arp_packet *arp){
    unsigned char *snd_hw_start;
    static char buf[80] = {0};
    if((ntohs(arp->hw_type) != ARP_ETHER) || (ntohs(arp->proto_type) != ETH_P_IP)){
        return "???";
    }

    snd_hw_start = ((unsigned char *) arp);
    snd_hw_start += sizeof(struct arp_packet);

    WriteAddr(buf, 80, NULL, snd_hw_start, eETH_ADDR);
    return buf;
}

void PrintExtraEtherInfo(struct eth_packet *eth_pkt){
	char *tmp = NULL;
	struct arp_packet *arp = NULL;
    struct eth_8021q_packet *q_pkt = (void *)(eth_pkt);

    if(!ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_8021Q)){
        printf(",vlan_prio=%d,cfi=%c,vlan_id=%d\nVlanEtherType=%s", q_pkt->priority, q_pkt->cfi ? 'T' : 'F', ntohs(q_pkt->vlan_id),GetEtherType(ntohs(q_pkt->ether_type)));
        return;
    }

    if(!ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_ARP)){
        tmp = (char *)eth_pkt;
        tmp += sizeof(struct eth_packet);
        arp = (struct arp_packet *) tmp;

        printf("\nARP HW Type: %x[%s]\n", ntohs(arp->hw_type),arp_hwtype_tostr(ntohs(arp->hw_type)));

        if(ntohs(arp->opcode) == ARP_REQUEST){
            printf("Who has ");
            printf("(%s)", GetEtherType(ntohs(arp->proto_type)));
            printf(" : %s; tell %s @ %s", arp_target_proto(arp), arp_sender_proto(arp), arp_sender_hw(arp));

        }else if(ntohs(arp->opcode) == ARP_REPLY){
            printf("(%s)", GetEtherType(ntohs(arp->proto_type)));
            printf(" : tell %s @ %s that %s is reached \n\tvia %s", arp_target_proto(arp), arp_target_hw(arp), arp_sender_proto(arp), arp_sender_hw(arp));

        }else{
        	printf("ARP OPCODE unknown :%d", ntohs(arp->opcode));
        }
        printf("\n");
    }
}

unsigned char convertAsciiHexCharToBin(char asciiHexChar){
    unsigned char binByte = 0xFF;

    if((asciiHexChar >= '0') && (asciiHexChar <= '9')){
        binByte = asciiHexChar - '0';
    }
    else if((asciiHexChar >= 'a') && (asciiHexChar <= 'f')){
        binByte = asciiHexChar - 'a' + 0x0A;
    }
    else if((asciiHexChar >= 'A') && (asciiHexChar <= 'f')){
        binByte = asciiHexChar - 'A' + 0x0A;
    }
    return binByte;
}

unsigned int ascii_to_bin(char *str_bin)
{
    /*converts an ascii string to binary*/
    char *out = NULL;
    char *str = NULL;
    int size_no_ws = 0;
    int outBufIdx = 0;
    int binBufIdx = 0;

    int rewind = 0;

    unsigned char firstNibble;
    unsigned char secondNibble;

    rewind = strlen(str_bin);

    if((out = (char*)malloc(8192)) == NULL){
    	perror("Allocation faild ascii function");
    	return EXIT_failure;
    }

    if((str = (char*)malloc(8192)) == NULL){
    	perror("Allocation faild ascii function");
    	return EXIT_failure;
    }

    while(*str_bin != 0)
        if(*str_bin++ != ' '){
            if(*(str_bin-1) == 'x'){
                *(str_bin-2) = *(str_bin-1)=' ';
                --size_no_ws;
                continue;
            }

            str[size_no_ws] = *(str_bin-1);
            size_no_ws++;
        }

    str_bin -= rewind;

    if((size_no_ws % 2) != 0){
        firstNibble = 0;
        secondNibble = convertAsciiHexCharToBin(str[0]);
        if(secondNibble == 0xFF){
            free(out);
            free(str);
            return EXIT_failure;
        }
        out[outBufIdx] = ((firstNibble<<4)&0xF0) | (secondNibble &0xF);
        outBufIdx++;
        binBufIdx = 1;
    }

    for(; binBufIdx < size_no_ws; binBufIdx += 2){
        firstNibble = convertAsciiHexCharToBin(str[binBufIdx]);
        secondNibble = convertAsciiHexCharToBin(str[binBufIdx+1]);

        if((firstNibble == 0xFF) || (secondNibble == 0xFF)){
            free(out);
            free(str);
            return EXIT_failure;
        }
        out[outBufIdx] = ((firstNibble<<4)&0xF0)|(secondNibble&0xF);
        outBufIdx++;
    }

    memcpy(str_bin, out, outBufIdx);
    free(out);
    free(str);

    return outBufIdx;
}

/*
 ============================================================================
 this is going to be crappy!
 brief Takes an IPv4 dotted-notation address and returns the binary
 representation.
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

    if(getaddrinfo(pIpStr, NULL, &hints, &servinfo) != 0){
        return EXIT_success;
    }

    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET){
            t = ((struct sockaddr_in*)(p->ai_addr))->sin_addr.s_addr;
            break;
        }else if(p->ai_family == AF_INET6){
            t = 1; /* for IPv6 we treat it as a "true" value */
        }else{
            t = 0;
        }
    }

    freeaddrinfo(servinfo);
    return t;
}

/* pcap dump frame: 8 bytes (64 bits) */

/*
 ============================================================================
 Dump the len bytes pointed to by b to file out.

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

    if(dump != NULL){
        out = dump;
    }

    for ( i = 0; i < len; i++ ){
        if ( cnt % 16 == 0 ){
            fprintf(out, "  %s\n%04X: ", str, cnt);
            memset(str, 0, 17);
        }
        if ( buf[cnt] < ' '  ||  buf[cnt] >= 127 ){
            str[cnt%16] = '.';
        }else{
            str[cnt%16] = buf[cnt];
        }
        fprintf(out, "%02X ", buf[cnt++]);
    }
    fprintf(out, "  %*s\n\n", 16+(16-len%16)*2, str);
}

char DumpPacket(char *buffer, int len, int quiet)
{
	tcpHdr *tcph = NULL;
	udpHdr *udph = NULL;

	struct eth_packet *eth_pkt = (void *)(buffer);
	struct ip_packet *ip = (void *)(buffer + (sizeof(eth_packet)));

    /* filter out the cruft - in userspace I know! */
    if(FILTER_CHK_MASK(filter_mask, ETH_SRC_FILTER)){
        if(!ethmask_cmp(eth_pkt->src_mac, eth_src_is_mac_filter)){
            if(eth_src_not){
                return EXIT_failure;
            }
        }else if(!eth_src_not){
            return EXIT_failure;
        }
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_DST_FILTER)){
        if(!ethmask_cmp(eth_pkt->dst_mac, eth_dst_is_mac_filter)){
            if(eth_dst_not){
                return EXIT_failure;
            }
        }else if (!eth_dst_not){
            return EXIT_failure;
        }
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_TYPE_FILTER)){
        if(!ethtype_cmp(ntohs(eth_pkt->eth_type), eth_type_is_filter)){
            if(eth_type_not){
                return EXIT_failure;
            }
        }else if(!eth_type_not){
            return EXIT_failure;
        }
    }

    if(FILTER_CHK_MASK(filter_mask, ETH_VLAN_FILTER)){
        if(!ethvlan_cmp(eth_pkt, eth_vlan_is_filter)){
            if(eth_vlan_not){
                return EXIT_failure;
            }
        }else if(!eth_vlan_not){
            return EXIT_failure;
        }
    }

    if(eth_contains_ip(eth_pkt)){
        ip = (void *)(buffer + (eth_contains_ip(eth_pkt)-1));

        if(FILTER_CHK_MASK(filter_mask, IP_SRC_FILTER)){
            if(ipcmp(ip->ip_src.IPv4_src, ip_src_is_filter)){
                if(ip_src_not){
                    return EXIT_failure;
                }
            }else if(!ip_src_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter_mask, IP_DST_FILTER)){
            if(ipcmp(ip->ip_dst.IPv4_dst, ip_dst_is_filter)){
                if(ip_dst_not){
                    return EXIT_failure;
                }
            }else if(!ip_dst_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter_mask, IP_TOS_BYTE_FILTER)){
            if(ip->serve_type == ip_tos_byte_filter){
                if(ip_tos_byte_filter_not){
                    return EXIT_failure;
                }
            }else if (!ip_tos_byte_filter_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter_mask, IP_PROTO_FILTER)){
            if(ip->protocol == ipproto_is_filter){
                if(ipproto_not){
                    return EXIT_failure;
                }
            }else if (!ipproto_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter_mask, UDP_TCP_SPORT_FILTER)){
            if(!udptcp_sport_cmp(ip, udp_tcp_sport_is_filter)){
                if(udp_tcp_sport_not){
                    return EXIT_failure;
                }
            }else if(!udp_tcp_sport_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter_mask, UDP_TCP_DPORT_FILTER)){
            if(udptcp_sport_cmp(ip, udp_tcp_dport_is_filter)){
                if(udp_tcp_dport_not){
                    return EXIT_failure;
                }
            }else if(!udp_tcp_dport_not){
                return EXIT_failure;
            }
        }
    }

    if(!(eth_contains_ip(eth_pkt)) && need_IP == 1){
        return EXIT_failure;
    }

    if(quiet){ // if quiet equal to 1 = display
        printf("-------------------------------------------------\n");
        dump(buffer, len, NULL);

        PrintAddr("Destination EtherID=", eth_pkt->dst_mac, eETH_ADDR);
        PrintAddr(", Source EtherID=", eth_pkt->src_mac, eETH_ADDR);
        printf("\nEthertype=%s", GetEtherType(ntohs(eth_pkt->eth_type)));

        PrintExtraEtherInfo(eth_pkt);
        if(eth_contains_ip(eth_pkt)){

        	tcph = NULL;
        	udph = NULL;

            if(ip->protocol == 0x06){
                buffer = buffer + (eth_contains_ip(eth_pkt));
                buffer = buffer + (ip->header_len * 4);
                tcph = (tcpHdr *)buffer;
            }

            if(ip->protocol == 0x11){
                buffer = buffer + (eth_contains_ip(eth_pkt));
                buffer = buffer + (ip->header_len * 4);
                udph = (udpHdr *)buffer;
            }

            printf("\nIPv%d: header-len=%d, type=%d, packet-size=%d, ID=%d\n",ip->version, ip->header_len*4, ip->serve_type,ntohs(ip->packet_len), ntohs(ip->ID));
            printf("no-frag=%c, more=%c, offset=%d, TTL=%d, protocol=%s\n",(ip->dont_frag? 'N': 'Y'),(ip->more_frags? 'N': 'Y'),ip->frag_offset,ip->time_to_live, GetProtocol(ip->protocol));
            printf("checksum=%x", ntohs(ip->hdr_chksum));

            ip->hdr_chksum = 0;
            ip->hdr_chksum = (unsigned short)checksum((unsigned short *)ip,ip->header_len*4);

            printf(" C:[%x], ", ntohs(ip->hdr_chksum));
            PrintAddr("source=", ip->ip_src.IPv4_src, eIP_ADDR);
            PrintAddr(", destination=", ip->ip_dst.IPv4_dst, eIP_ADDR);
            printf("\n");

            if(tcph){
                printf("TCP Flags: ");
                if(tcph->options.flags.urg){
                    printf("URG ");
                }
                if(tcph->options.flags.ack){
                    printf("ACK ");
                }
                if(tcph->options.flags.psh){
                    printf("PSH ");
                }
                if(tcph->options.flags.rst){
                    printf("RST ");
                }
                if(tcph->options.flags.syn){
                    printf("SYN ");
                }
                if(tcph->options.flags.fin){
                    printf("FIN ");
                }
                printf("\n");

                printf("[TCP] transport layer cksum=%x", tcph->cksum);
                tcph->cksum = 0;
                printf(",calc'd=%x",  (unsigned short) get_tcp_checksum(ip, tcph));
                printf(",sport=%d,dport=%d", ntohs(tcph->srcPort),
                       ntohs(tcph->dstPort));
            }
            else if (udph){
            	unsigned short cksum;
                printf("[UDP] transport layer cksum=%x", udph->cksum);
                cksum = udph->cksum;
                udph->cksum = 0;
                printf(",calc'd=%x",  cksum ? (unsigned short) get_udp_checksum(ip, udph) : 0);
                printf(",sport=%d,dport=%d", ntohs(udph->srcPort),ntohs(udph->dstPort));
            }
        }
        printf("\n");
        fflush(stdout);
    }

    return EXIT_success;
}

int run = 1;

void terminate_hnd(int sig){
    run = 0;
}

int sniff_nano_sleep(const struct timespec *req, struct timespec *remain){
    struct timespec _remainder;
    if(nanosleep(req, remain) == -1){
        sniff_nano_sleep(remain, &_remainder);
    }

    return EXIT_success;
}

void pcap_pkt_sleep(struct timeval *pPacketCurrent,struct timeval *pPacketLast){
    struct timespec delta = {0}, remainder = {0};

    if(pPacketLast->tv_sec == 0){
        return;
    }

    if( (pPacketCurrent->tv_sec < pPacketLast->tv_sec) || ((pPacketCurrent->tv_sec == pPacketLast->tv_sec) && (pPacketCurrent->tv_usec < pPacketLast->tv_usec))){
        return;
    }

    delta.tv_sec = pPacketCurrent->tv_sec - pPacketLast->tv_sec;
    delta.tv_nsec = 1000 * (pPacketCurrent->tv_usec - pPacketLast->tv_usec);

    sniff_nano_sleep(&delta, &remainder);
}

int main(int argc, char *argv[]){

	/* Declaration */
	FILE *pcap_dump_file = NULL;

	int sd=-1;
	int bytes_read;
	int display = 1;
	int result = 0;

	char res = 0;
	char *rdata;
	char *data;
	char infomercial[15]={0};
	char *lastarg = NULL;
	char pcap_input = 0;
	char pcap_byteswap = 0;
	char *pcap_fname = NULL;
	char *iface = NULL;

	struct sockaddr_ll s1;
	struct sockaddr_in sa;
	struct ifreq interface_obj;
	struct timeval tv;
	struct timeval rcvtime;
	struct timeval lasttime = {0};
	struct timeval curtime = {0};

	uint sl;
	uchar notflag = 0;

	pcap_hdr_t in_pcap_header;
	pcap_hdr_t pcap_header;
	pcaprec_hdr_t pcap_rec;
	pcaprec_hdr_t pcap_hdr;

	fd_set readfd;

	/* NEW */
	unsigned long int pkts_rx = 0;
	unsigned long int pkts_pass = 0;

    /*
	=================================================================
	CAP_NET_ADMIN: Promiscuous mode and a truckload of other
				   stuff we don't need (and shouldn't have).
	CAP_NET_RAW:   Packet capture (raw sockets).
	=================================================================
    */
    cap_value_t cap_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };

    /* POSIX signals */
    signal(SIGABRT, &terminate_hnd); // The SIGABRT signal is sent to a process to tell it to abort, i.e. to terminate.
    signal(SIGTERM, &terminate_hnd); // The SIGTERM signal is sent to a process to request its termination.
    signal(SIGINT, &terminate_hnd); // The SIGINT signal is sent to a process by its controlling terminal when a user wishes to interrupt the process.

    /* Determine if process is running as root */
    if (getuid() != 0) {
		printf("This program must run as root\n");
		return EXIT_failure;
	}

    /*
     =================================================================
     Running logged in as root (euid=0; ruid=0). Using libcap.
     Action:
     Near to start of program: Drop all other capabilities other then
     NET_RAW and NET_ADMIN by using cap_enable() function.
     =================================================================
    */
    if (cap_enable(cap_list) == EXIT_failure) {
    	return EXIT_failure;
    }

    if(argc > 1){ // If argument count bigger then 1
        while(--argc){ //run on all opening argument
            if(strncmp("--", argv[argc], 2)){ // check for valid opening argument
                if(strcmp("!", argv[argc])){ // check for NOT option in opening argument
                    lastarg = argv[argc];
                }else{
                    notflag = 1;
                }
            }else{

                if((lastarg == NULL) && strchr(argv[argc],'=')){ // ???
                    lastarg = strchr(argv[argc],'=');
                    ++lastarg;
                }

                if((lastarg) && lastarg[0] == '!'){
                    ++lastarg;
                    notflag = 1;
                }

                if(!strncmp("--help", argv[argc], 6)){ // print CL options
                	print_usage();
                	return EXIT_success;
                }

                else if(!strncmp("--quiet", argv[argc], 7)){ /* CHOOSE RETHEAR TO keep the QUIET option ? */
                    display=0;
                }

                else if(!strncmp("--interface", argv[argc], 11) && lastarg != NULL){
                    iface = lastarg;
                }

                else if(!strncmp("--input", argv[argc], 7) && lastarg != NULL){
                    pcap_input = 1;
                    pcap_fname = lastarg;
                    notflag = 0;
                }
                else if(!strncmp("--not", argv[argc], 5) && lastarg != NULL){
                    notflag = 1;
                    continue;
                }
                else if(!strncmp("--output", argv[argc], 8) && lastarg != NULL){
                    printf("Sniffer start pcap execution...\n");
                    pcap_dump_file = fopen(lastarg, "w+r");

                    if(pcap_dump_file == NULL) {
                        printf("unable to save pcap file. aborting.\n");
                        perror("fopen");
                        return EXIT_failure;
                    }

                    pcap_header.magic_number  = 0xa1b2c3d4;
                    pcap_header.version_major = 2;
                    pcap_header.version_minor = 4;
                    pcap_header.thiszone      = 0;
                    pcap_header.sigfigs       = 0;
                    pcap_header.snaplen       = 65535;
                    pcap_header.network       = 1;

                    fwrite((void *)&pcap_header, sizeof(pcap_header), 1, pcap_dump_file);
                    fflush(pcap_dump_file);
                    notflag = 0;
                }
                else if(!strncmp("--vlan-id", argv[argc], 9) && lastarg != NULL){
                    FILTER_SET_MASK(filter_mask, ETH_VLAN_FILTER);
                    eth_vlan_is_filter = strtol(lastarg,NULL,0);
                    if(notflag){
                    	eth_vlan_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--eth-src", argv[argc], 9) && lastarg != NULL){
                    FILTER_SET_MASK(filter_mask, ETH_SRC_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(eth_src_is_mac_filter, infomercial, 6);
                    if(notflag){
                    	eth_src_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--eth-dst", argv[argc], 9) && lastarg != NULL){
                    FILTER_SET_MASK(filter_mask, ETH_DST_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(eth_dst_is_mac_filter, infomercial, 6);
                    if(notflag){
                    	eth_dst_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--eth-type", argv[argc], 10) && lastarg != NULL){
                    FILTER_SET_MASK(filter_mask, ETH_TYPE_FILTER);
                    eth_type_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	eth_type_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-src", argv[argc], 7) && lastarg != NULL){
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_SRC_FILTER);
                    ip_src_is_filter = atoip(lastarg);
                    if(notflag){
                    	ip_src_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-dst", argv[argc], 7) &&lastarg != NULL){
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_DST_FILTER);
                    ip_dst_is_filter = atoip(lastarg);
                    if(notflag){
                    	ip_dst_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-tos", argv[argc], 8) &&lastarg != NULL){
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_TOS_BYTE_FILTER);
                    ip_tos_byte_filter = strtol(lastarg, NULL, 0);
                    if(notflag) {
                    	ip_tos_byte_filter_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-proto", argv[argc], 10) && lastarg != NULL){
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, IP_PROTO_FILTER);
                    ipproto_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	ipproto_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-sport", argv[argc], 10) && lastarg != NULL){
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, UDP_TCP_SPORT_FILTER);
                    udp_tcp_sport_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	udp_tcp_sport_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-dport", argv[argc], 10) && lastarg != NULL){
                    need_IP = 1;
                    FILTER_SET_MASK(filter_mask, UDP_TCP_DPORT_FILTER);
                    udp_tcp_dport_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	udp_tcp_dport_not = 1;
                    }
                    notflag = 0;

                }else{
                    printf("UNKNOWN OPTION, %s,%s\n", argv[argc], lastarg);
                    print_usage();
                    return EXIT_failure;
                }
                lastarg = NULL;
            }
        }
    }
    /* rdata allocation */
    rdata = (char *)malloc(65535);

    /*  error check for rdata allocation */
    if(!rdata){
    	fprintf(stderr, "Sniffer: OOM\n"); // Prints Out of memory
    	return EXIT_failure;
    }

    if(!pcap_input){
        /*doesn't work with OS X*/
        sd = socket(SOCK_FAM_TYPE, SOCK_RAW, SOCK_PROTO_TYPE);

        if ( sd < 0 ){
            perror("socket");
            return EXIT_failure;
        }

    } else { //writing pcap output

        sd = open(pcap_fname, O_RDWR); // open flag O_RDWR Permits all system calls to be executed.

        if(sd < 1){
            perror("open");
            return EXIT_failure;
        }

    	if(read(sd, &in_pcap_header, sizeof(in_pcap_header)) < 0){
            perror("read");
            return EXIT_failure;
    	}

        if(in_pcap_header.magic_number == 0xa1b2c3d4){
        /* we don't need to byteswap the packet info. */
        }
        else if (in_pcap_header.magic_number == 0xd4c3b2a1){

            pcap_byteswap = 1 ;
            in_pcap_header.version_major = endian_swap_16(in_pcap_header.version_major);
            in_pcap_header.version_minor = endian_swap_16(in_pcap_header.version_minor);
            in_pcap_header.thiszone		 = endian_swap_32(in_pcap_header.thiszone);
            in_pcap_header.sigfigs       = endian_swap_32(in_pcap_header.sigfigs);
            in_pcap_header.snaplen       = endian_swap_32(in_pcap_header.snaplen);
            in_pcap_header.network       = endian_swap_32(in_pcap_header.network);

        }else{
            fprintf(stderr,"ERROR: Pcap file corrupt / bad magic number [%X]\n",in_pcap_header.magic_number);
        	return EXIT_failure;
        }

        if(in_pcap_header.network != 1){
            fprintf(stderr, "Error: Sniffer only works on ethernet caps.\n");
        	return EXIT_failure;
        }

        printf("pcap info:\n");
        printf("network: Ethernet (always)\n");
        printf("tz:      %d\n", in_pcap_header.thiszone);
        printf("snaplen: %u\n", in_pcap_header.snaplen);
        printf("version: %d.%d\n", in_pcap_header.version_major, in_pcap_header.version_minor);
    }

    if(iface){

        memset(&s1, 0, sizeof(struct sockaddr_ll));
        strcpy((char *)interface_obj.ifr_name, iface);

        result = ioctl(sd, SIOCGIFINDEX, &interface_obj);

        if(result >= 0) {
        	result = interface_obj.ifr_ifindex;
            s1.sll_family = SOCK_FAM_TYPE;
            s1.sll_ifindex = result;
            s1.sll_protocol = SOCK_PROTO_TYPE;
            result = bind(sd, (struct sockaddr *)&s1, sizeof(s1));

            if(result < 0) {
                printf("unable to bind to device.\n");
                return EXIT_failure;
            }
        }

    }do {

        tv.tv_sec = 0;
        tv.tv_usec = 5000; /* 5ms */

        FD_ZERO(&readfd);
        data = rdata;

        if(!pcap_input){
            sl = sizeof(struct sockaddr_in);
            FD_SET(sd, &readfd);
            bytes_read = select(sd+1, &readfd, NULL, NULL, &tv);

            if(bytes_read > 0){
				bytes_read = recvfrom(sd, data, 65535, 0, (struct sockaddr *)&sa, &sl);

				rcvtime.tv_sec = time(NULL);
				/* we do this because on some platforms, notably embedded,
				gettimeofday can "forget" to populate tv_sec. */
				rcvtime.tv_usec = 0;
				gettimeofday(&rcvtime, NULL);
            }else{
                bytes_read = 1;
                continue;
            }
        }else{
            if(read(sd, &pcap_rec, sizeof(pcap_rec)) < 0){
            	perror("read");
                bytes_read = 0;
                run = 0;
                continue;
            }

            if(pcap_byteswap){
                pcap_rec.ts_sec = endian_swap_32(pcap_rec.ts_sec);
                pcap_rec.ts_usec = endian_swap_32(pcap_rec.ts_usec);
                pcap_rec.incl_len = endian_swap_32(pcap_rec.incl_len);
                pcap_rec.orig_len = endian_swap_32(pcap_rec.orig_len);
            }

            curtime.tv_sec = pcap_rec.ts_sec;
            curtime.tv_usec = pcap_rec.ts_usec;

            pcap_pkt_sleep(&curtime, &lasttime);

            memcpy(&lasttime, &curtime, sizeof(lasttime));

            bytes_read = read(sd, data, pcap_rec.incl_len);
        }

        if ( bytes_read > 0 ){

            res = DumpPacket(data, bytes_read, display);
            ++pkts_rx;

			if(!res) {
				++pkts_pass;
			}

            if(pcap_dump_file && res == 0) {

                rcvtime.tv_sec = time(NULL);
                rcvtime.tv_usec = 0;
                gettimeofday(&rcvtime, NULL);

                pcap_hdr.ts_sec = rcvtime.tv_sec;
                pcap_hdr.ts_usec = rcvtime.tv_usec;
                pcap_hdr.incl_len = bytes_read;
                pcap_hdr.orig_len = bytes_read;

                fwrite((void *)&pcap_hdr, sizeof(pcap_hdr), 1, pcap_dump_file);
                fwrite((void *)data, 1, bytes_read, pcap_dump_file);
                fflush(pcap_dump_file);
            }

        }else if(bytes_read == -1){
            perror("Sniffer read");
            return EXIT_failure;
        }
    }
    while (run && bytes_read > 0 );

    printf("\nTerminating...\n");
    free(rdata);

    if(pcap_dump_file){
        fclose(pcap_dump_file);
    }

	printf("Packets captured: %lu\n", pkts_rx);

	if(pkts_pass != pkts_rx){
		printf("Packets matching: %lu\n", pkts_pass);
	}

    return EXIT_success;
}
