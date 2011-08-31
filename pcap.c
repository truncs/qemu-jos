#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "pcap.h"

static int started = 0;
static FILE *cap_file;

static void
pcap_write(const char *b, int l) {
	size_t c = fwrite(b, 1, l, cap_file);
	assert(c == l);
	fflush(cap_file);
}

void
pcap_dump_init(const char *fname) {
	pcap_hdr_t pcap_hdr;

	if (!fname)
		fname = "slirp.cap";

	cap_file = fopen(fname, "wb");
	if (!cap_file) {
		perror("pcap_dump_init:");
		return;
	}

	pcap_hdr.magic_number = PCAP_MAGIC;
	pcap_hdr.version_major = PCAP_VMAJOR;
	pcap_hdr.version_minor = PCAP_VMINOR;
	pcap_hdr.thiszone = 0;
	pcap_hdr.sigfigs = 0;
	pcap_hdr.snaplen = 65535;
	pcap_hdr.network = 1; // Ethernet

	pcap_write((char *)&pcap_hdr, sizeof(pcap_hdr));

	started = 1;
}

void
pcap_dump(const uint8_t *pkt, int len) {
	pcaprec_hdr_t pkt_hdr;
	struct timeval tv;

	if (!started)
		return;

	gettimeofday(&tv, 0);

	pkt_hdr.ts_sec = tv.tv_sec;
	pkt_hdr.ts_usec = tv.tv_usec;
	pkt_hdr.incl_len = len;
	pkt_hdr.orig_len = len;

	pcap_write((char *)&pkt_hdr, sizeof(pkt_hdr));
	pcap_write(pkt, len);
}
