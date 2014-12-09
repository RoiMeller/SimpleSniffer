/*! \file IP.h
 * 	\brief Header for IP model.
 *
 * 	The file contain all the IP related types  , defines , structs  and function declaration
 *  */



#ifndef IP_H_
#define IP_H_

# include "GOhdr.h"
/* Global declaration */
# define IP_SIZE  4
/** \def IP_SIZE
	the golbal size for the arrays in IP structs
 	 */



/*! \struct ip_packet Ethernet.h
 * 	\brief this is an IP packet Struct
	============================================================================
	 This structure defines the fields within the IP frame. Since this program
	 gets the lowest-level packet, fragmented packets are not reassembled.
	 The first few fields contain the MAC addresses of the source and destination.
	 Note that this structure is set for little-endian format.

	 So I cheated and stole someone else's IP header and changed it... sue me :)
	============================================================================
 * 		  */
struct ip_packet {

#ifdef __LITTLE_ENDIAN__
    uint header_len:4;
    uint version:4;
#else	/*__LITTLE_ENDIAN__ */
    uint version:4;					/*!< 4-bit version */
    uint header_len:4;				/*!< header length in words in 32bit words */
#endif	/*__LITTLE_ENDIAN__ */
    uint serve_type:8;				/*!< how to service packet */
    uint packet_len:16;				/*!< total size of packet in bytes */
    uint ID:16;						/*!< fragment ID */
#ifdef __LITTLE_ENDIAN__
    uint frag_offset:13;
    uint more_frags:1;				/*!< flag for "more frags to follow" */
    uint dont_frag:1;				/*!< flag to permit fragmentation */
    uint __reserved:1;				/*!< always zero */
#else	/*__LITTLE_ENDIAN__ */
    uint __reserved:1;				/*!< always zero */
    uint more_frags:1;				/*!< flag for "more frags to follow" */
    uint dont_frag:1;				/*!< flag to permit fragmentation */
    uint frag_offset:13;			/*!< to help reassemble */
#endif	/*__LITTLE_ENDIAN__ */
    uint time_to_live:8;			/*!< maximum router hop count */
    uint protocol:8;				/*!< ICMP, UDP, TCP */
    uint hdr_chksum:16;				/*!< ones-comp. checksum of header */


    union {
        uint  addr:32;
        uchar IPv4_src[IP_SIZE];	/*!< IP address of originator */
    } ip_src;

    union {
        uint  addr:32;
        uchar IPv4_dst[IP_SIZE];	/*!< IP address of destination */
    } ip_dst;

    uchar options[0];				/*!< up to 40 bytes */
    uchar data[0];					/*!< message data up to 64KB */
};

/* Function declaration */


/** \fn int ipcmp(uchar *ipstruct_addr, int addr);
	\brief compare the ip address to the given address

	\param ipstruct_addr an unsigned character pointer contain the address in IP struct
	\param addr an integer contain the given address
	\return 1 for success and 0 for failure

 */
int ipcmp(uchar *ipstruct_addr, int addr);

/** \fn int atoip(const char *pIpStr);
 * 	\brief Takes an IPv4 dotted-notation address and returns the binary
 	 representation.

 	 \param pIpStr A dotted-notation IPv4 address.
 	 \return an IP Address, if one could be looked up. If pIpStr is actually
 	 IPv6, returns 1. If there was an error, returns -1 or 0.
 * */
int atoip(const char *pIpStr);

/** \fn char *GetProtocol(uint value);
 * 	\brief check which ip protocol is in the struct.
 *
 * 	the function check the given integer and return the name of the protocol it related to
 * 	\param value an unsigned integer contain the protocol number
 * 	\return character pointer contain the name of the protocol.
 *
 * */
char *GetProtocol(uint value);

#endif /* IP_H_ */
