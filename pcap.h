#ifndef _PCAP_H_
#define _PCAP_H_

#include "qemu-common.h"

/*
 * Used http://wiki.wireshark.org/Development/LibpcapFileFormat to get the pcap file format
 */

#define PCAP_MAGIC	0xa1b2c3d4
#define PCAP_VMAJOR	2
#define PCAP_VMINOR	4

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

void pcap_dump_init(const char *fname);
void pcap_dump(const uint8_t *pkt, int len);

#endif //_PCAP_H_
