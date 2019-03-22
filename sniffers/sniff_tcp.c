#include <netinet/tcp.h>
#include "defs.h"

void sniff_tcp(const unsigned char *packet, int verbosity, int *packet_size, unsigned short *src_port, unsigned short *dst_port)
{
  struct tcphdr *header;
  unsigned char flags;

  header = (struct tcphdr *)(packet + *packet_size);
  *packet_size += sizeof(*header);
  *src_port = ntohs(header->th_sport);
  *dst_port = ntohs(header->th_dport);
  flags = header->th_flags;

  printf("   >>> TCP\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("source port: %i\n", *src_port);
  printf("destination port: %i\n", *dst_port);
  printf("sequence number: 0x%.4x\n", ntohl(header->th_seq));
  printf("acknowledgment number: 0x%.4x\n", ntohl(header->th_ack));
  printf("data offset: %i\n", header->th_off);
  printf("flags: ");
  if (flags & TH_URG)
    printf("URG ");
  if (flags & TH_ACK)
    printf("ACK ");
  if (flags & TH_RST)
    printf("RST ");
  if (flags & TH_PUSH)
    printf("PSH ");
  if (flags & TH_SYN)
    printf("SYN ");
  if (flags & TH_FIN)
    printf("FIN ");
  printf("\n");
  printf("window: 0x%.4x\n", ntohs(header->th_win));
  printf("checksum: 0x%.4x\n", ntohs(header->th_sum));
  printf("urgent pointer: 0x%.4x\n", ntohs(header->th_urp));
}