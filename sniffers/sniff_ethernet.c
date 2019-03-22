#include <netinet/if_ether.h>
#include "defs.h"

void sniff_ethernet(const unsigned char *packet, int verbosity, int *packet_size, int *next_protocol)
{
  struct ether_header *header;
  int i;

  header = (struct ether_header *)packet;
  *packet_size += sizeof(*header);
  *next_protocol = ntohs(header->ether_type);

  printf("   >>> ETHERNET\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("source MAC address: ");
  for (i = 0; i < 5; i++)
    printf("%.2x:", header->ether_shost[i]);
  printf("%.2x\n", header->ether_shost[5]);

  printf("destination MAC address: ");
  for (i = 0; i < 5; i++)
    printf("%.2x:", header->ether_dhost[i]);
  printf("%.2x\n", header->ether_shost[5]);
}