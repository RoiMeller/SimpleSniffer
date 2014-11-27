#ifndef GOHDR_H_
#define GOHDR_H_

# include <stdio.h>				// For standard things
# include <time.h>

/* Global declaration */
# define ERROR_PRINT perror
# define EXIT_success 0
# define EXIT_failure -1

# ifdef __BYTE_ORDER
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define __LITTLE_ENDIAN__ 1
#  else
#   if __BYTE_ORDER == __BIG_ENDIAN
#    define __BIG_ENDIAN__ 1
#   else
#    error "Unknown byte order"
#   endif
#  endif /* __BYTE_ORDER */
# endif

/* Socket descriptor definition */
# define SOCK_FAM_TYPE PF_PACKET /* packet interface on device level - Every packet */
# define SOCK_PROTO_TYPE htons(ETH_P_ALL) /* Host byte order to network byte order */

/* Defining a parameterized macro */
#define FILTER_CHK_MASK(a,b) (((uint)a&(uint)b) == (uint)b) // The function check for mask value in mask filter
#define FILTER_SET_MASK(a,b) (!FILTER_CHK_MASK(a,b)?a |= b : a) // Return 'b' if 0. 'a' otherwise

typedef unsigned char uchar;
typedef unsigned int uint;

/* Global variable */
int run = 1;

/* Filter mask value for mask check and set */
uint  filter_mask = 0;

/* Function decloration */
void print_usage();
unsigned char convertAsciiHexCharToBin(char asciiHexChar);
unsigned int ascii_to_bin(char *str_bin);
void dump(void* b, int len, FILE *dump);
char DumpPacket(char *buffer, int len, int quiet);
int sniff_nano_sleep(const struct timespec *req, struct timespec *remain);
void terminate_hnd(int sig);

#endif /* GOHDR_H_ */
