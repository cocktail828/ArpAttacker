//################################################################
//############ Date: September 4 2012
//############ Author: Vincent Dary
//############ File: ArpSpoof.h
//############ Licence: GPLv3
//############ Description: network and packet forge functions
//################################################################

#ifndef ARPSPOOF_H_INCLUDED
#define ARPSPOOF_H_INCLUDED

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "CmdLineTtmt.h"

struct ArpPacket
{
	struct ethernetHeader	etherLayer;
	struct arpHeader	arpLayer;
};

void	hex_dump(const unsigned char *buffer, size_t size);
void 	set_arp_packet(const struct ArpSpoof *ttmtData, struct ArpPacket *fakeArp);
int 	open_l2_link(const char *interface);
void	arp_injection(const struct ArpPacket *fakeArp, const int sock);
void	arp_spoofing(const int argc, const char *argv[]);

#endif
