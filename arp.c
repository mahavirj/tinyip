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

struct arp_hdr {
	uint16_t hwtype;
	uint16_t protype;
	unsigned char hwsize;
	unsigned char prosize;
	uint16_t opcode;
	unsigned char data[];
} __attribute__((packed));

struct arp_ipv4 {
	unsigned char smac[6];
	uint32_t sip;
	unsigned char dmac[6];
	uint32_t dip;
} __attribute__((packed));

struct arp_cache {
	uint16_t proto;
	uint32_t ip;
	unsigned char mac[6];
	list_head_t next;
};

static LIST_HEAD(head);
#define ETHERNET 0x0001
#define IPV4	0x0800
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0001
static uint32_t myip = 0x0200000a;
static char mymac[] = {0x00, 0x50, 0x43, 0x78, 0x89, 0x9a};

int arp_in(struct arp_hdr *hdr)
{
	assert(hdr);

	if (ntohs(hdr->hwtype) != ETHERNET)
		return -EINVAL;

	if (ntohs(hdr->protype) != IPV4)
		return -EINVAL;

	struct arp_ipv4 *arpd = (struct arp_ipv4 *) hdr->data;
	bool merge_flag = false;
	struct arp_cache *arpc;	

	list_for_each_entry(arpc, &head, next) {
		if (arpc->ip == arpd->sip) {
			memcpy(arpc->mac, arpd->smac, 6); 
			merge_flag = true;
			break;
		}
	}

	if (arpd->dip == myip) {
		if (!merge_flag) {
			arpc = (struct arp_cache *) malloc(sizeof(struct arp_cache));
			if (!arpc)
				return -ENOMEM;
			arpc->ip = arpd->sip;
			arpc->proto = hdr->protype;
			memcpy(arpc->mac, arpd->smac, 6);
			list_add(&arpc->next, &head);
		}

		if (ntohs(hdr->opcode) == ARP_REQUEST) {
			hdr->opcode = htons(ARP_REPLY);
			uint32_t tmp = arpd->dip;
			arpd->dip = arpd->sip;
			arpd->sip = tmp;
			memcpy(arpd->dmac, arpd->smac, 6);
			memcpy(arpd->smac, mymac, 6);
		}
	}

	return 0;
}
