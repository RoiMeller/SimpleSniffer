#ifndef ARP_H_
#define ARP_H_

/* Address Resolution Protocol */

# include "Ethernet.h"
# include "GOhdr.h"

/* Global ARP definition */

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

/* ARP Struct */
struct arp_packet {
    uint  hw_type    : 16; 	// This field specifies the network protocol type. Example: Ethernet is 1
    uint  proto_type : 16; 	// This field specifies the internetwork protocol for which the ARP request is intended. For IPv4, this has the value 0x0800.
    uchar alen;				// Length (in octets) of a hardware address. Ethernet addresses size is 6.
    uchar proto_alen;		// Length (in octets) of addresses used in the upper layer protocol.
    uint  opcode     : 16; 	// Specifies the operation that the sender is performing: 1 for request, 2 for reply.
};

struct address_format {
    int len;
    char *fmt;
    char delim;
};

/* ARP Function declorayion */
char *arp_target_hw(struct arp_packet *arp);
char *arp_sender_proto(struct arp_packet *arp);
char *arp_sender_hw(struct arp_packet *arp);
char *arp_target_proto(struct arp_packet *arp);
char *arp_hwtype_tostr(unsigned short hwtype);
void WriteAddr(char *buf, unsigned int buflen, char *msg, unsigned char *addr, EAddress is_ip);
void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip);

#endif /* ARP_H_ */
