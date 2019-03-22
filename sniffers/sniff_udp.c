#include <netinet/udp.h>
#include "defs.h"

void sniff_udp(const unsigned char *packet, int verbosity, int *packet_size, unsigned short *src_port, unsigned short *dst_port)
{
  struct udphdr *header;

  header = (struct udphdr *)(packet + *packet_size);
  *packet_size += sizeof(*header);
  *src_port = ntohs(header->uh_sport);
  *dst_port = ntohs(header->uh_dport);

  printf("   >>> UDP\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("source port: %i\n", *src_port);
  printf("destination port: %i\n", *dst_port);
  printf("total length: %i\n", ntohs(header->uh_ulen));
  printf("checksum: 0x%.4x\n", ntohs(header->uh_sum));
}