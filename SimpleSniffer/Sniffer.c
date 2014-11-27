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
# include <arpa/inet.h>			// uint32_t and uint16_t
# include <net/ethernet.h>		// For ether_header
# include <errno.h>				// Defines macros for reporting and retrieving error conditions
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
# include <linux/prctl.h>
# include <netdb.h>				// definitions for network database operations
# include <sys/socket.h>		// Declarations of socket constants, types, and functions
# include <sys/types.h>			// Various data types

# include "GOhdr.h"
# include "WSPCAP.h"
# include "Ethernet.h"
# include "IP.h"
# include "TCP_UDP.h"
# include "ARP.h"

/* GLOBAL Ethernet VARIABLES */


static int run = 1;


void terminate_hnd(int sig){
    run = 0;
}
char DumpPacket(char *buffer, int len, int quiet, struct filter *filter){
	tcpHdr *tcph = NULL;
	udpHdr *udph = NULL;

	struct eth_packet *eth_pkt = (void *)(buffer);
	struct ip_packet *ip = (void *)(buffer + (sizeof(eth_packet)));

    /* filter out the cruft - in userspace I know! */
    if(FILTER_CHK_MASK(filter->filter_mask, ETH_SRC_FILTER)){
        if(!ethmask_cmp(eth_pkt->src_mac, filter->eth_src_is_mac_filter)){
            if(filter->eth_src_not){
                return EXIT_failure;
            }
        }else if(!filter->eth_src_not){
            return EXIT_failure;
        }
    }

    if(FILTER_CHK_MASK(filter->filter_mask, ETH_DST_FILTER)){
        if(!ethmask_cmp(eth_pkt->dst_mac, filter->eth_dst_is_mac_filter)){
            if(filter->eth_dst_not){
                return EXIT_failure;
            }
        }else if (!filter->eth_dst_not){
            return EXIT_failure;
        }
    }

    if(FILTER_CHK_MASK(filter->filter_mask, ETH_TYPE_FILTER)){
        if(!ethtype_cmp(ntohs(eth_pkt->eth_type), filter->eth_type_is_filter)){
            if(filter->eth_type_not){
                return EXIT_failure;
            }
        }else if(!filter->eth_type_not){
            return EXIT_failure;
        }
    }

    if(FILTER_CHK_MASK(filter->filter_mask, ETH_VLAN_FILTER)){
        if(!ethvlan_cmp(eth_pkt, filter->eth_vlan_is_filter)){
            if(filter->eth_vlan_not){
                return EXIT_failure;
            }
        }else if(!filter->eth_vlan_not){
            return EXIT_failure;
        }
    }

    if(eth_contains_ip(eth_pkt)){
        ip = (void *)(buffer + (eth_contains_ip(eth_pkt)));

        if(FILTER_CHK_MASK(filter->filter_mask, IP_SRC_FILTER)){
            if(ipcmp(ip->ip_src.IPv4_src, filter->ip_src_is_filter)){
                if(filter->ip_src_not){
                    return EXIT_failure;
                }
            }else if(!filter->ip_src_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter->filter_mask, IP_DST_FILTER)){
            if(ipcmp(ip->ip_dst.IPv4_dst,filter->ip_dst_is_filter)){
                if(filter->ip_dst_not){
                    return EXIT_failure;
                }
            }else if(!filter->ip_dst_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter->filter_mask, IP_TOS_BYTE_FILTER)){
            if(ip->serve_type == filter->ip_tos_byte_filter){
                if(filter->ip_tos_byte_filter_not){
                    return EXIT_failure;
                }
            }else if (!filter->ip_tos_byte_filter_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter->filter_mask, IP_PROTO_FILTER)){
            if(ip->protocol == filter->ipproto_is_filter){
                if(filter->ipproto_not){
                    return EXIT_failure;
                }
            }else if (!filter->ipproto_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter->filter_mask, UDP_TCP_SPORT_FILTER)){
            if(!udptcp_sport_cmp(ip, filter->udp_tcp_sport_is_filter)){
                if(filter->udp_tcp_sport_not){
                    return EXIT_failure;
                }
            }else if(!filter->udp_tcp_sport_not){
                return EXIT_failure;
            }
        }

        if(FILTER_CHK_MASK(filter->filter_mask, UDP_TCP_DPORT_FILTER)){
            if(udptcp_sport_cmp(ip, filter->udp_tcp_dport_is_filter)){
                if(filter->udp_tcp_dport_not){
                    return EXIT_failure;
                }
            }else if(!filter->udp_tcp_dport_not){
                return EXIT_failure;
            }
        }
    }

    if(!(eth_contains_ip(eth_pkt)) && filter->need_IP == 1){
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

/* MAIN */
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
	struct filter filter = {{0}};
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
                    FILTER_SET_MASK(filter.filter_mask, ETH_VLAN_FILTER);
                    filter.eth_vlan_is_filter = strtol(lastarg,NULL,0);
                    if(notflag){
                    	filter.eth_vlan_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--eth-src", argv[argc], 9) && lastarg != NULL){
                    FILTER_SET_MASK(filter.filter_mask, ETH_SRC_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(filter.eth_src_is_mac_filter, infomercial, 6);
                    if(notflag){
                    	filter.eth_src_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--eth-dst", argv[argc], 9) && lastarg != NULL){
                    FILTER_SET_MASK(filter.filter_mask, ETH_DST_FILTER);
                    memcpy(infomercial, lastarg, 12);
                    ascii_to_bin(infomercial);
                    memcpy(filter.eth_dst_is_mac_filter, infomercial, ETH_ALEN);
                    if(notflag){
                    	filter.eth_dst_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--eth-type", argv[argc], 10) && lastarg != NULL){
                    FILTER_SET_MASK(filter.filter_mask, ETH_TYPE_FILTER);
                    filter.eth_type_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	filter.eth_type_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-src", argv[argc], 7) && lastarg != NULL){
                	filter.need_IP = 1;
                    FILTER_SET_MASK(filter.filter_mask, IP_SRC_FILTER);
                    filter.ip_src_is_filter = atoip(lastarg);
                    if(notflag){
                    	filter.ip_src_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-dst", argv[argc], 7) &&lastarg != NULL){
                	filter.need_IP = 1;
                    FILTER_SET_MASK(filter.filter_mask, IP_DST_FILTER);
                    filter.ip_dst_is_filter = atoip(lastarg);
                    if(notflag){
                    	filter.ip_dst_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-tos", argv[argc], 8) &&lastarg != NULL){
                	filter.need_IP = 1;
                    FILTER_SET_MASK(filter.filter_mask, IP_TOS_BYTE_FILTER);
                    filter.ip_tos_byte_filter = strtol(lastarg, NULL, 0);
                    if(notflag) {
                    	filter.ip_tos_byte_filter_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-proto", argv[argc], 10) && lastarg != NULL){
                	filter.need_IP = 1;
                    FILTER_SET_MASK(filter.filter_mask, IP_PROTO_FILTER);
                    filter.ipproto_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	filter.ipproto_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-sport", argv[argc], 10) && lastarg != NULL){
                	filter.need_IP = 1;
                    FILTER_SET_MASK(filter.filter_mask, UDP_TCP_SPORT_FILTER);
                    filter.udp_tcp_sport_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	filter.udp_tcp_sport_not = 1;
                    }
                    notflag = 0;
                }
                else if(!strncmp("--ip-dport", argv[argc], 10) && lastarg != NULL){
                	filter.need_IP = 1;
                    FILTER_SET_MASK(filter.filter_mask, UDP_TCP_DPORT_FILTER);
                    filter.udp_tcp_dport_is_filter = strtol(lastarg, NULL, 0);
                    if(notflag){
                    	filter.udp_tcp_dport_not = 1;
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

//      memset(rdata,'\0',65535);

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

            res = DumpPacket(data, bytes_read, display,&filter);
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

