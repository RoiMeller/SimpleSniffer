
# include "Ethernet.h"
# include "GOhdr.h"
# include "ARP.h"
# include "IP.h"
# include "TCP_UDP.h"
# include <stdio.h>				// For standard things
# include <stdint.h>			// Declare sets of integer types having specified widths, and shall define corresponding sets of macros.
# include <stdlib.h>			// malloc / EXIT_SUCCESS = 0, EXIT_FAILURE = 1
# include <string.h>			// strlen
# include <netinet/in.h>		// Internet Protocol family
# include <netinet/tcp.h>		// Provides declarations for tcp header

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

unsigned int ascii_to_bin(char *str_bin){
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

char DumpPacket(char *buffer, int len, int quiet){
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


int sniff_nano_sleep(const struct timespec *req, struct timespec *remain){
    struct timespec _remainder;
    if(nanosleep(req, remain) == -1){
        sniff_nano_sleep(remain, &_remainder);
    }

    return EXIT_success;
}


void terminate_hnd(int sig){
    run = 0;
}

