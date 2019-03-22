#include "net/ipv6.h"
#include "defs.h"

void sniff_ipv6(const unsigned char *packet, int verbosity, int *packet_size, int *next_protocol)
{
  struct ipv6hdr *header;
  int i;
  char *buf;

  header = (struct ipv6hdr *)(packet + *packet_size);
  *packet_size += sizeof(*header);
  *next_protocol = (int)header->ipv6_nextheader;

  printf("   >>> IPv6\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("traffic class: 0x%.2x\n", header->ipv6_priority);
  printf("flow label: Ox");
  for (i = 0; i < 3; i++)
    printf("%.2x", header->ipv6_flow_lbl[i]);
  printf("\n");
  printf("payload length: %i\n", ntohs(header->ipv6_len));
  printf("protocol: 0x%.2x ", *next_protocol);
  if (*next_protocol == 0x06)
    printf("(TCP)\n");
  else if (*next_protocol == 0x11)
    printf("(UDP)\n");
  else
    printf("(unsupported protocol)\n");
  printf("hop limit: %i\n", header->ipv6_hoplimit);
  inet_ntop(AF_INET6, &(header->ipv6_src), buf, INET6_ADDRSTRLEN);
  printf("source IP address: %s\n", buf);
  inet_ntop(AF_INET6, &(header->ipv6_dst), buf, INET6_ADDRSTRLEN);
  printf("destination IP address: %s\n", buf);
}