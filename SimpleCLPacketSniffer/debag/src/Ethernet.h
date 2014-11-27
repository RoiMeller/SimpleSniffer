#ifndef ETHERNET_H_
#define ETHERNET_H_

# include "GOhdr.h"
# include "IP.h"

/* Global Ethernet definition */

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
                                         * defined in draft-wilson-wrec-wccp-v2-00.txt */
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

/* Ethernet addresses are 6 bytes */
#define ETH_ALEN 6

typedef enum { eETH_ADDR, eIP_ADDR } EAddress;

/* Ethernet Struct's */
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

/* GLOBAL Ethernet VARIABLES */
uchar eth_src_is_mac_filter[ETH_ALEN];
uchar eth_src_not = 0;

uchar eth_dst_is_mac_filter[ETH_ALEN];
uchar eth_dst_not = 0;

uint  eth_type_is_filter;
uchar eth_type_not = 0;

uint  eth_vlan_is_filter;
uchar eth_vlan_not = 0;

/* Ethernet Function Declaration */
char *GetEtherType(int eth_type);
int eth_contains_ip(struct eth_packet *eth_pkt);
void WriteAddr(char *buf, unsigned int buflen, char *msg, unsigned char *addr, EAddress is_ip);
void PrintAddr(char* msg, unsigned char *addr, EAddress is_ip);
char *GetProtocol(uint value);
int ethmask_cmp(unsigned char *retr_addr, unsigned char *filter_addr);
int ethtype_cmp(uint retr_type, uint filter_type);
int ethvlan_cmp(struct eth_packet *eth_pkt, uint vlan_tag);
void PrintExtraEtherInfo(struct eth_packet *eth_pkt);

#endif /* ETHERNET_H_ */
