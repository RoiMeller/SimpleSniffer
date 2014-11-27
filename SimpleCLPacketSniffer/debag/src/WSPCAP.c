# include <sys/types.h>			// Various data types
# include <sys/capability.h>
# include <linux/capability.h>	// _LINUX_CAPABILITY_VERSION
# include <unistd.h>			// Provides access to the POSIX operating system API

# include "GOhdr.h"
# include "WSPCAP.h"

/* PCAP Header BYTEORDER & size */
inline unsigned int endian_swap_32(unsigned int x){ 

    x = (x>>24)               |
        ((x<<8) & 0x00ff0000) |
        ((x>>8) & 0x0000ff00) |
        (x<<24)               ;
    return x;
}

/* PCAP Header BYTEORDER & size */
inline unsigned short endian_swap_16(unsigned short x){ 

    x = (x>>8)|
        (x<<8);
    return x;
}

/*
 ===============================================================
 If we were linked with libcap (not related to libpcap) and
 If we started with special privs (ie: suid) then enable for
 ourself the  NET_ADMIN and NET_RAW capabilities and then
 drop our suid privileges.
 ===============================================================
*/
int cap_enable(cap_value_t cap_list[]) {

    int cl_len = 0 ;
    char * name = NULL;
    cap_t caps = cap_init();   /* all capabilities initialized to off */

    uid_t ruid;
    uid_t euid;
    gid_t rgid;
    gid_t egid;

	ruid = getuid();
	euid = geteuid();
	rgid = getgid();
	egid = getegid();

	cl_len = sizeof(cap_list) / sizeof(cap_value_t);

	/*
	 ======================================================
	 Worked thank's to WireShark source code documentation

	 If we were started with special privileges, set the
	 real and effective group and user IDs to the original
	 values of the real and effective group and user IDs.

	 (Set the effective UID last - that takes away our
 	 rights to set anything else.)
	 ======================================================
	*/

	/* Real and effective group IDs */
	if (setgid(rgid) == -1) {
		perror("setgid");
		return EXIT_failure;
	}
	if (setegid(rgid) == -1) {
		perror("setegid");
		return EXIT_failure;
	}

	/* Real and effective user IDs */
	if (setuid(ruid) == -1) {
		perror("setuid");
		return EXIT_failure;
	}
	if (seteuid(ruid) == -1) {
		perror("seteuid");
		return EXIT_failure;
	}

    if(cap_set_flag(caps, CAP_PERMITTED,   cl_len, cap_list, CAP_SET) == -1 ){
    	perror("cap_set_flag() set permitted fail return");
    	return EXIT_failure;
    }
    if (cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET) == -1){
    	perror("cap_set_flag() set permitted fail return");
    	return EXIT_failure;
    }
    if(cap_set_flag(caps, CAP_EFFECTIVE, cl_len, cap_list, CAP_SET) == -1){
    	perror("cap_set_flag() set permitted fail return");
    	return EXIT_failure;
    }

    if (cap_set_proc(caps)) {
    	perror("cap_set_proc() fail return");
    	return EXIT_failure;
    }

    name = cap_to_text(caps, NULL);
    printf("After setting: getuid: %d geteuid: %d Capabilities : %s\n", getuid(), geteuid(), name);

    if (cap_free(caps) == -1){
    	perror("CAP_FREE");
    	return EXIT_failure;
    }

    if (cap_free(name) == -1){
    	perror("CAP_FREE");
    	return EXIT_failure;
    }
    return EXIT_success;
}

void pcap_pkt_sleep(struct timeval *pPacketCurrent,struct timeval *pPacketLast){
    struct timespec delta = {0}, remainder = {0};

    if(pPacketLast->tv_sec == 0){
        return;
    }

    if( (pPacketCurrent->tv_sec < pPacketLast->tv_sec) || ((pPacketCurrent->tv_sec == pPacketLast->tv_sec) && (pPacketCurrent->tv_usec < pPacketLast->tv_usec))){
        return;
    }

    delta.tv_sec = pPacketCurrent->tv_sec - pPacketLast->tv_sec;
    delta.tv_nsec = 1000 * (pPacketCurrent->tv_usec - pPacketLast->tv_usec);

    sniff_nano_sleep(&delta, &remainder);
}
