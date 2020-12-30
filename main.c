//################################################################
//############ Date: September 4 2012
//############ Author: Vincent Dary
//############ File: main.c
//############ Licence: GPLv3
//############ Description: the ArpSpoof program entry point
//################################################################

#include "ArpSpoof.h"

int main(int argc, char *argv[])
{
	arp_spoofing(argc, (const char**)argv);

	return 0;
}
