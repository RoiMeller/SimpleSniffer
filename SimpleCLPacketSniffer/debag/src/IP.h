#ifndef IP_H_
#define IP_H_

# include "GOhdr.h"
/* Global declaration */
# define IP_SIZE  4


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
    uint header_len:4;				/* header length in words in 32bit words */
    uint version:4;					/* 4-bit version */
#else	/*!__LITTLE_ENDIAN__ */
    uint version:4;
    uint header_len:4;
#endif	/*!__LITTLE_ENDIAN__ */
    uint serve_type:8;				/* how to service packet */
    uint packet_len:16;				/* total size of packet in bytes */
    uint ID:16;						/* fragment ID */
#ifdef __LITTLE_ENDIAN__
    uint frag_offset:13;			/* to help reassemble */
    uint more_frags:1;				/* flag for "more frags to follow" */
    uint dont_frag:1;				/* flag to permit fragmentation */
    uint __reserved:1;				/* always zero */
#else	/*!__LITTLE_ENDIAN__ */
    uint __reserved:1;
    uint more_frags:1;
    uint dont_frag:1;
    uint frag_offset:13;
#endif	/*!__LITTLE_ENDIAN__ */
    uint time_to_live:8;			/* maximum router hop count */
    uint protocol:8;				/* ICMP, UDP, TCP */
    uint hdr_chksum:16;				/* ones-comp. checksum of header */

    union {
        uint  addr:32;
        uchar IPv4_src[IP_SIZE];	/* IP address of originator */
    } ip_src;

    union {
        uint  addr:32;
        uchar IPv4_dst[IP_SIZE];	/* IP address of destination */
    } ip_dst;

    uchar options[0];				/* up to 40 bytes */
    uchar data[0];					/* message data up to 64KB */
};



/* Function declaration */
int ipcmp(uchar *ipstruct_addr, int addr);
int atoip(const char *pIpStr);
char *GetProtocol(uint value);


#endif /* IP_H_ */
