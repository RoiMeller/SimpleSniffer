
# include <sys/socket.h>
# include <stdio.h>
# include "GOhdr.h"



int ipcmp(uchar *ipstruct_addr, int addr){

	int ipstr_addr = *((int*)ipstruct_addr);

    return (addr) ? ((addr == ipstr_addr) ? 1 : 0) : 0;
}



/*
 ============================================================================
 this is going to be crappy!
 brief Takes an IPv4 dotted-notation address and returns the binary
 representation.

 param pIpStr A dotted-notation IPv4 address.
 return an IP Address, if one could be looked up. If pIpStr is actually
 IPv6, returns 1. If there was an error, returns -1 or 0.
 ============================================================================
*/
int atoip(const char *pIpStr){
    struct addrinfo hints, *servinfo, *p;
    int t = 0;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(pIpStr, NULL, &hints, &servinfo) != 0){
        return EXIT_success;
    }

    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if(p->ai_family == AF_INET){
            t = ((struct sockaddr_in*)(p->ai_addr))->sin_addr.s_addr;
            break;
        }else if(p->ai_family == AF_INET6){
            t = 1; /* for IPv6 we treat it as a "true" value */
        }else{
            t = 0;
        }
    }

    freeaddrinfo(servinfo);
    return t;
}

