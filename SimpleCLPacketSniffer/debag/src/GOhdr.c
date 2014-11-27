# include <stdio.h>				// For standard things
# include <stdint.h>			// Declare sets of integer types having specified widths, and shall define corresponding sets of macros.
# include <stdlib.h>			// malloc / EXIT_SUCCESS = 0, EXIT_FAILURE = 1
# include <string.h>			// strlen
# include <netinet/in.h>		// Internet Protocol family
# include <netinet/tcp.h>		// Provides declarations for tcp header

# include "GOhdr.h"
# include "Ethernet.h"
# include "IP.h"
# include "TCP_UDP.h"


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


int sniff_nano_sleep(const struct timespec *req, struct timespec *remain){
    struct timespec _remainder;
    if(nanosleep(req, remain) == -1){
        sniff_nano_sleep(remain, &_remainder);
    }

    return EXIT_success;
}


