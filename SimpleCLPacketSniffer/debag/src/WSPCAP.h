#ifndef WSPCAP_H_
#define WSPCAP_H_

# include <arpa/inet.h>			// uint32_t and uint16_t

# include "GOhdr.h"

/*
 ==================================================================================================
 Definitions and descriptions come from: http://wiki.wireshark.org/Development/LibpcapFileFormat
 ==================================================================================================
*/
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

/* Function declaration */
inline unsigned int endian_swap_32(unsigned int x);
inline unsigned short endian_swap_16(unsigned short x);
int cap_enable(cap_value_t cap_list[]);
void pcap_pkt_sleep(struct timeval *pPacketCurrent,struct timeval *pPacketLast);

#endif /* WSPCAP_H_ */
