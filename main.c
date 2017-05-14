#include <stdlib.h>
#include <stdbool.h>
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

#define CLEAR(x) memset(&x, 0, sizeof(x))
#define print_error printf

struct eth_hdr {
	unsigned char dmac[6];
	unsigned char smac[6];
	uint16_t ethertype;
	unsigned char payload[];
} __attribute__((packed));

int tun_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		print_error("Cannot open TUN/TAP dev");
		exit(1);
	}

	CLEAR(ifr);

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if( *dev ) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		print_error("ERR: Could not ioctl tun: %s\n", strerror(errno));
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

int tun_read(int fd, char *buf, int len)
{
	return read(fd, buf, len);
}

static char macaddr[] = {0x00, 0x50, 0x43, 0x78, 0x89, 0x9a};
#define BUFLEN 1536
static char buf[BUFLEN];

bool is_unicast(unsigned char *mac)
{
	return !memcmp(macaddr, mac, 6);
}

bool is_broadcast(unsigned char *mac)
{
	return ((mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff);
}

int main()
{
	char test[32] = "tap0";
	int ret;
	int fd = tun_alloc(test);

	do {
		if ((ret = tun_read(fd, buf, BUFLEN)) < 0) {
			print_error("ERR: Read from tun_fd: %s\n", strerror(errno));
			break;
		}

		struct eth_hdr *hdr = (struct eth_hdr *) buf;
		if (!is_unicast(hdr->dmac) && !is_broadcast(hdr->dmac))
			continue;

		switch (ntohs(hdr->ethertype)) {
			case ETH_P_RARP:
				printf("rarp packet, ignore!\n");
				break;
			case ETH_P_ARP:
				printf("arp packet\n");
				arp_in(hdr->payload);
				memcpy(hdr->dmac, hdr->smac, 6);
				memcpy(hdr->smac, macaddr, 6);
				ret = write(fd, buf, ret);
				break;
			case ETH_P_IP:
				printf("ip packet\n");
				ip_in(hdr->payload);
				memcpy(hdr->dmac, hdr->smac, 6);
				memcpy(hdr->smac, macaddr, 6);
				ret = write(fd, buf, ret);
				break;
			default:
				printf("drop unkown-type packet\n");
				break;
		}

	} while(1);

	return 0;
}
