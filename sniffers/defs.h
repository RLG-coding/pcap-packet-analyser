// includes
#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// ethernet header protocol numbers
#define IPV4 0x0800
#define IPV6 0x86DD
#define ARP 0x0806

// IP header protocol numbers
#define TCP 0x06
#define UDP 0x11

// ports
#define DHCPS 67
#define DHCPD 68
#define DNS 53