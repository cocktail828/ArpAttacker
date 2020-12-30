//################################################################
//############ Date: September 4 2012
//############ Author: Vincent Dary
//############ File: CmdLineTtmt.h
//############ Licence: GPLv3
//############ Description: processing the command line
//################################################################

#ifndef CMDLINETTMT_H_INCLUDED
#define CMDLINETTMT_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "NetHeader.h"


#define STRING_MAC_SIZE         17

// Contains all information for a MITM attack
struct ArpSpoof
{
        char interface[IFNAMSIZ];
        unsigned char targetMac[ETHERNET_ADDR_LEN];
        unsigned char targetIp[IPV4_ADDR_LEN];
        unsigned char sourceMac[ETHERNET_ADDR_LEN];
        unsigned char fakeIp[IPV4_ADDR_LEN];
};


int 	interface_check(const char *interface);
int 	str_mac_check(const char *strMac);
int 	str_ipv4_check(const char *ip);
int 	check_cmd_spoof(const char *argv[]);
void 	set_cmd_spoof(const char *argv[], struct ArpSpoof *spoofData);
int 	cmd_ttmt(const int argc, const char *argv[], struct ArpSpoof *spoofData);

#endif
