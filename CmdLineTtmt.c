//################################################################
//############ Date: September 4 2012
//############ Author: Vincent Dary
//############ File: CmdLineTtmt.c
//############ Licence: GPLv3
//############ Description: processing the command line
//################################################################

#include "CmdLineTtmt.h"

// Performs the network interface verification in the string representation.
//
// parameters:
//              interface: the network interface in the string representation
//
// return: 0 if the mac address is valid or -1 if the adress is invalid.
//
int interface_check(const char *interface)
{
	if(strlen(interface) > IFNAMSIZ)
		return -1;

	return 0;
}

// Performs the mac address verification in the string representation.
//
// parameters:
//		strMac: a mac address in the string representation
//
// return: 0 if the mac address is valid or -1 if the adress is invalid.
//
int str_mac_check(const char *strMac)
{
	int i = 0;

	if(strlen(strMac) != STRING_MAC_SIZE)
		return -1;

	for(i=0; i<STRING_MAC_SIZE; ++i)
	{
		if(i==2)
		{
			if(strMac[i] != ':')
				return -1;
		}
		else if(i==5)
		{
			if(strMac[i] != ':')
                                return -1;
		}
		else if(i==8)
		{
			if(strMac[i] != ':')
                                return -1;
		}
		else if(i==11)
		{
			if(strMac[i] != ':')
                                return -1;
		}
		else if(i==14)
		{
			if(strMac[i] != ':')
                                return -1;
		}
		else
		{
			if(strMac[i] < 0x30 || strMac[i] > 0x39)
                                if(strMac[i] < 0x61 || strMac[i] > 0x66)
                                        if(strMac[i] < 0x41 || strMac[i] > 0x46)
                                                return -1;
		}
	}

	return 0;
}

// Performs the ip address verification in the string representation.
//
// parameters:
//              strMac: a ip address in the string representation
//
// return: 0 if the ip addess is valid or -1 if the adress is invalid.
//
int str_ipv4_check(const char *ip)
{
        unsigned int binIp = 0;

        if(ip == NULL)
                return -1;

        if(inet_pton(AF_INET, ip, &binIp) == 0)
               return -1;

        return 0;
}



// Checks the command line's parameters.
//
// parameters:
//		argv: the command line table
//
// return: return: 0 if all the parameters are valid or -1.
//
int check_cmd_spoof(const char *argv[])
{
	if(interface_check(argv[1]) < 0)
        {
		printf("[-] argument 1 : invalid interface : %s\n", argv[1]);
                return -1;
       	}

	if(str_mac_check(argv[2]) <0)
	{
		printf("[-] argument 2 : invalid mac address : %s\n", argv[2]);
                return -1;
	}
	if(str_ipv4_check(argv[3]) <0)
	{
		printf("[-] argument 3 : invalid ip address : %s\n", argv[3]);
		return -1;
	}
	if(str_mac_check(argv[4]) <0)
	{
		printf("[-] argument 4 : invalid mac address : %s\n", argv[4]);
		return -1;
	}
	if(str_ipv4_check(argv[5]) <0)
	{
		printf("[-] argument 5 : invalid ip address : %s\n", argv[5]);
		return -1;
	}

	return 0;
}

// Sets the spoofData structure with the command line's parameters.
//
// parameters:
//		argv: the command line table
//		spoofData: an ArpSpoof structure for store the the command line's parameters
//
// return: return: 0 if all the parameters are valid or -1.
//
void set_cmd_spoof(const char *argv[], struct ArpSpoof *spoofData)
{
	memset(spoofData, 0, sizeof(struct ArpSpoof));
	strncpy(spoofData->interface, argv[1], IFNAMSIZ);

	sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                        &(spoofData->targetMac[0]), &(spoofData->targetMac[1]), &(spoofData->targetMac[2]),
                                        &(spoofData->targetMac[3]), &(spoofData->targetMac[4]), &(spoofData->targetMac[5]));

	sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd",	&(spoofData->targetIp[0]), &(spoofData->targetIp[1]),
						&(spoofData->targetIp[2]), &(spoofData->targetIp[3]));

        sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                        &(spoofData->sourceMac[0]), &(spoofData->sourceMac[1]), &(spoofData->sourceMac[2]),
                                        &(spoofData->sourceMac[3]), &(spoofData->sourceMac[4]), &(spoofData->sourceMac[5]));

	sscanf(argv[5], "%hhd.%hhd.%hhd.%hhd",  &(spoofData->fakeIp[0]), &(spoofData->fakeIp[1]),
                                        	&(spoofData->fakeIp[2]), &(spoofData->fakeIp[3]));
}

// The treatment of the command's line.
//
// parameters:
//		argc: the comand line's parameters number
//		argv: the command line table
//		spoofData: an ArpSpoof structure for store the the command line's parameters
//
// return: 0 if all the parameters are valid or -1.
//
int cmd_ttmt(const int argc, const char *argv[], struct ArpSpoof *spoofData)
{
	if(argc != 6)
	{
		puts("\n usage: ArpSpoof <interface> <target mac> <target IPv4> <source mac> <fake IPv4>\n");
		return -1;
	}
	else
	{
		if(check_cmd_spoof(argv) < 0)
			return -1;

		set_cmd_spoof(argv, spoofData);
	}

	return 0;
}
