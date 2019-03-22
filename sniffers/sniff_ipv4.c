#include <netinet/ip.h>
#include "defs.h"

void sniff_ipv4(const unsigned char *packet, int verbosity, int *packet_size, int *next_protocol)
{
  struct ip *header;

  header = (struct ip *)(packet + *packet_size);
  *packet_size += sizeof(*header);
  *next_protocol = header->ip_p;

  printf("   >>> IPv4\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("header length (IHL): %i\n", header->ip_hl);
  printf("type of service (ToS): 0x%.2x\n", header->ip_tos);
  printf("total length: %i\n", ntohs(header->ip_len));
  printf("identification: 0x%.4x\n", ntohs(header->ip_id));
  if (ntohs(header->ip_off) == 0x4000)
    printf("fragment offset field: 0x4000 (DON'T FRAGMENT)\n");
  else
    printf("fragment offset field: 0x2000 (MORE FRAGMENT)\n");
  printf("time to live: %i\n", header->ip_ttl);
  printf("protocol: 0x%.2x ", *next_protocol);
  if (*next_protocol == 0x06)
    printf("(TCP)\n");
  else if (*next_protocol == 0x11)
    printf("(UDP)\n");
  else
    printf("(unsupported protocol)\n");
  printf("checksum: 0x%.4x\n", ntohs(header->ip_sum));
  printf("source IP address: %s\n", inet_ntoa(header->ip_src));
  printf("destination IP address: %s\n", inet_ntoa(header->ip_dst));
}