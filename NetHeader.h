//################################################################
//############ Date: September 4 2012
//############ Author: Vincent Dary
//############ File: NetHeader.h
//############ Licence: GPLv3
//############ Description: network header
//################################################################

#ifndef NETHEADER_H_INCLUDED
#define NETHEADER_H_INCLUDED

#include <sys/ioctl.h>
#include <net/if.h>

// field type length
#define ETHERNET_ADDR_LEN       6
#define IPV4_ADDR_LEN           4

// layer type length
#define ETHERNET_LAYER_LEN	14
#define ARP_LAYER_LEN		28

// packet type length
#define ARP_PACKET_LEN		42

// Ethernet header
struct ethernetHeader
{
	unsigned char		macDest[ETHERNET_ADDR_LEN];
	unsigned char   	macSrc[ETHERNET_ADDR_LEN];
	unsigned short int	etherType;
};

// Arp header for IPv4
struct arpHeader
{
	unsigned short int      hardwareType;
	unsigned short int	protocolType;

	unsigned char		hardwareAddrLength;
	unsigned char		protocolAddrLength;

	unsigned short int	operation;

	unsigned char		sendHardwareAddr[ETHERNET_ADDR_LEN];
	unsigned char		sendIpAddr[IPV4_ADDR_LEN];

	unsigned char		targetHardwareAddr[ETHERNET_ADDR_LEN];
	unsigned char		TargetIpAddr[IPV4_ADDR_LEN];
};

#endif

