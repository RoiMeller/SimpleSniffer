/*! \file Ethernet.h
 * 	\brief Header for Ethernet model.
 *
 * 	The file contain all the Ethernet related types  , defines , structs  and function declaration
 *  */

#ifndef ETHERNET_H_
#define ETHERNET_H_

# include "GOhdr.h"
# include "IP.h"

/* Global Ethernet definition */

/* the following defines are taken from if_ether.h */
# define ETH_P_IP        0x0800          /**< Internet Protocol packet     */
# define ETH_P_X25       0x0805          /**< CCITT X.25                   */
# define ETH_P_ARP       0x0806          /**< Address Resolution packet    */
# define ETH_P_BPQ       0x08FF          /**< G8BPQ AX.25 Ethernet Packet  [ NOT AN OFFICIALLY REGISTERED ID ] */
# define ETH_P_IEEEPUP   0x0a00          /**< Xerox IEEE802.3 PUP packet */
# define ETH_P_IEEEPUPAT 0x0a01          /**< Xerox IEEE802.3 PUP Addr Trans packet */
# define ETH_P_DEC       0x6000          /**< DEC Assigned proto           */
# define ETH_P_DNA_DL    0x6001          /**< DEC DNA Dump/Load            */
# define ETH_P_DNA_RC    0x6002          /**< DEC DNA Remote Console       */
# define ETH_P_DNA_RT    0x6003          /**< DEC DNA Routing              */
# define ETH_P_LAT       0x6004          /**< DEC LAT                      */
# define ETH_P_DIAG      0x6005          /**< DEC Diagnostics              */
# define ETH_P_CUST      0x6006          /**< DEC Customer use             */
# define ETH_P_SCA       0x6007          /**< DEC Systems Comms Arch       */
# define ETH_P_RARP      0x8035          /**< Reverse Addr Res packet      */
# define ETH_P_ATALK     0x809B          /**< Appletalk DDP                */
# define ETH_P_AARP      0x80F3          /**< Appletalk AARP               */
# define ETH_P_8021Q     0x8100          /**< 802.1Q VLAN Extended Header  */
# define ETH_P_IPX       0x8137          /**< IPX over DIX                 */
# define ETH_P_IPV6      0x86DD          /**< IPv6 over bluebook           */
# define ETH_P_PAUSE     0x8808          /**< IEEE Pause frames. See 802.3 31B */
# define ETH_P_SLOW      0x8809          /**< Slow Protocol. See 802.3ad 43B */
# define ETH_P_WCCP      0x883E          /**< Web-cache coordination protocol */
                                         /* defined in draft-wilson-wrec-wccp-v2-00.txt */
# define ETH_P_PPP_DISC  0x8863          /**< PPPoE discovery messages     */
# define ETH_P_PPP_SES   0x8864          /**< PPPoE session messages       */
# define ETH_P_MPLS_UC   0x8847          /**< MPLS Unicast traffic         */
# define ETH_P_MPLS_MC   0x8848          /**< MPLS Multicast traffic       */
# define ETH_P_ATMMPOA   0x884c          /**< MultiProtocol Over ATM       */
# define ETH_P_ATMFATE   0x8884          /**< Frame-based ATM Transport*/
                                          /* over Ethernet                                         */
# define ETH_P_AOE       0x88A2          /**< ATA over Ethernet            */
# define ETH_P_TIPC      0x88CA          /**< TIPC                         */

/* FIlter value reference for mask check and set */
#define ETH_DST_FILTER       0x00000002 /**< Ethernet destination filter value            */
#define ETH_SRC_FILTER       0x00000001 /**< Ethernet source filter value            */
#define ETH_TYPE_FILTER      0x00000004 /**< Ethernet type filter value             */
#define ETH_VLAN_FILTER      0x00000008 /**< Ethernet VLAN filter value             */
#define IP_SRC_FILTER        0x00000010 /**< IP source filter value             */
#define IP_DST_FILTER        0x00000020 /**< IP destination filter value            */
#define IP_PROTO_FILTER      0x00000040 /**< IP protocol filter value            */
#define UDP_TCP_SPORT_FILTER 0x00000080 /**< UDP TCP source port filter value            */
#define UDP_TCP_DPORT_FILTER 0x00000100 /**< UDP TCP destination port filter value            */
#define IP_TOS_BYTE_FILTER   0x00002000 /**< IP type of service byte filter value            */

/** Ethernet addresses are 6 bytes */
#define ETH_ALEN 6
/** \typedef Ethernet address enum */
typedef enum { eETH_ADDR, eIP_ADDR } EAddress;

/* Ethernet Struct's */
/*! \struct eth_packet Ethernet.h
 * 	\brief this is an Ethernet packet Struct
 *
 * 	\var dst_mac an array for destination mac
 * 	\var src_mac an array for source mac
 * 	\var eth_type an Ethernet Type	  */
struct eth_packet {
    uchar dst_mac[ETH_ALEN];
    uchar src_mac[ETH_ALEN];
    uint  eth_type:16;
}eth_packet;

/*! \struct eth_8021q_packet Ethernet.h
 * 	\brief this is an Ethernet 802.1q packet Struct
 *
 * 	\var dst_mac an array for destination mac
 * 	\var src_mac an array for source mac
 * 	\var eth_type an Ethernet Type
 * 	\var priority size 3
 * 	\var cfi size 1
 * 	\var vlan_id size 12
 * 	\var ether_type size 16
 * 	 */
struct eth_8021q_packet {
    uchar dst_mac[ETH_ALEN];
    uchar src_mac[ETH_ALEN];
    uint  eth_type:16;
    uint  priority: 3;
    uint  cfi: 1;
    uint  vlan_id: 12;
    uint  ether_type:16;
};

/* Ethernet Function Declaration */
/** \fn char *GetEtherType(int eth_type)
 * 	\brief get Ethernet type.
 *
 * 	\param  eth_type a integer contains the Ethernet type in an number.
 * 	\return a character pointer that points to the Ethernet type name  */
char *GetEtherType(int eth_type);

/** \fn int eth_contains_ip(struct eth_packet *eth_pkt)
 * 	\brief check for IP in Ethernet header.
 *
 * 	the function recieve an Ethernet packet and return the length of the IP header.
 *
 * 	\param  eth_pkt a pointer to a struct eth_packet contains the Ethernet packet.
 * 	\return a integer contians the length of the IP header  */
int eth_contains_ip(struct eth_packet *eth_pkt);

/** \fn int ethmask_cmp(unsigned char *retr_addr, unsigned char *filter_addr)
 * 	\brief
 *
 * 	\param  retr_addr unsigned character pointer
 *	\param  filter_addr	unsigned character pointer
 * 	\return a integer contians 0 for success and -1 for failure */
int ethmask_cmp(unsigned char *retr_addr, unsigned char *filter_addr);

/** \fn int ethtype_cmp(uint retr_type, uint filter_type)
 * 	\brief compare between the 2 parameters
 *
 * 	\param  retr_addr unsigned integer
 *	\param  filter_addr	unsigned integer
 * 	\return a integer contians 0 for success and -1 for failure */
int ethtype_cmp(uint retr_type, uint filter_type);

/** \fn int ethvlan_cmp(struct eth_packet *eth_pkt, uint vlan_tag);
 * 	\brief check for .1q type and vlan id.
 *
 * 	the function receive the Ethernet packet and return success for Ethernet type .1q and if not return success for correct vlan id
 * 	and failure otherwise
 *
 * 	\param  eth_pkt a pointer to a struct eth_packet contains the Ethernet packet.
 *	\param  vlan_tag	unsigned integer
 * 	\return a integer contains 0 for success and -1 for failure */
int ethvlan_cmp(struct eth_packet *eth_pkt, uint vlan_tag);

/** \fn void PrintExtraEtherInfo(struct eth_packet *eth_pkt)
 * 	\brief prints Ethernet information
 *
 * 	the function prints the full data from the Ethernet packet with vlan and arp details.
 *
 * 	\param  eth_pkt a pointer to a struct eth_packet contains the Ethernet packet.
 * 	*/

void PrintExtraEtherInfo(struct eth_packet *eth_pkt);

#endif /* ETHERNET_H_ */
