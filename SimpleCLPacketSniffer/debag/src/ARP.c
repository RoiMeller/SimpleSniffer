

# include "ARP.h"
# include "Ethernet.h"
# include "GOhdr.h"


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



