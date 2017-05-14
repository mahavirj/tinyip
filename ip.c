#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "list.h"

struct iphdr {
	uint8_t version : 4;
	uint8_t ihl : 4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t flags : 3;
	uint16_t frag_offset : 13;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));

struct icmp_v4 {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint8_t data[];
} __attribute__((packed));

struct icmp_v4_echo {
	uint16_t id;
	uint16_t seq;
	uint8_t data[];
} __attribute__((packed));

#define ICMP 0x01

uint16_t checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 * Taken from https://tools.ietf.org/html/rfc1071
	 */
	register uint32_t sum = 0;
	uint16_t * ptr = addr;

	while( count > 1 )  {
		/*  This is the inner loop */
		sum += * ptr++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if( count > 0 )
		sum += * (uint8_t *) addr;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

int ip_in(struct iphdr *hdr)
{
	assert(hdr);

	if (checksum(hdr, sizeof(*hdr))) {
		printf("ip: incorrect checksum\n");
		return -EINVAL;
	}

	if (hdr->daddr != 0x0200000a)
		return -EINVAL;

	if (hdr->proto == ICMP) {
		struct icmp_v4 *icmp = (struct icmp_v4 *) ((uintptr_t) hdr + sizeof(*hdr));
		if (icmp->type == 0x8) {
			uint32_t tmp;
			tmp = hdr->daddr;
			hdr->daddr = hdr->saddr;
			hdr->saddr = tmp;
			/* Recalculate checksum */
			hdr->csum = 0x0;
			hdr->csum = checksum(hdr, sizeof(*hdr));
			icmp->type = 0x0;
			icmp->csum = 0x0;
			icmp->csum = checksum(icmp, ntohs(hdr->len) - sizeof(*hdr));
		}
	}

	return 0;
}
