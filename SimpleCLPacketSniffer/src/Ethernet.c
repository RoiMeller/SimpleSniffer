# include <netinet/in.h>		// Internet Protocol family

# include "Ethernet.h"
# include "GOhdr.h"
# include "ARP.h"

/* Ethernet Function */

/* <linux/if_ether.h> These are the defined Ethernet Protocol ID's. */
char *GetEtherType(int eth_type){
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

void PrintExtraEtherInfo(struct eth_packet *eth_pkt){
	char *tmp = NULL;
	struct arp_packet *arp = NULL;
    struct eth_8021q_packet *q_pkt = (void *)(eth_pkt);

    if(!ethtype_cmp(ntohs(eth_pkt->eth_type), ETH_P_8021Q)){
        printf(",vlan_prio = %d, cfi = %c ,vlan_id = %d\nVlanEtherType=%s", q_pkt->priority, q_pkt->cfi ? 'T' : 'F', ntohs(q_pkt->vlan_id),GetEtherType(ntohs(q_pkt->ether_type)));
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
