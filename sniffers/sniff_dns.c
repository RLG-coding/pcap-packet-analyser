#include "net/dns.h"
#include "defs.h"

void sniff_dns(const unsigned char *packet, int verbosity, int *packet_size)
{
  struct dnshdr *header;
  unsigned short flags;

  header = (struct dnshdr *)(packet + *packet_size);
  *packet_size += sizeof(*header);

  printf("   >>> DNS\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("identifier: 0x%.4x\n", header->id);
  printf("message type: ");
  if (header->qr)
    printf("response\n");
  else
    printf("query\n");
  printf("operation code: %i\n", header->opcode);
  printf("response code: %i\n", header->rcode);
  printf("flags: ");
  if (header->aa)
    printf("AA ");
  if (header->tc)
    printf("TC ");
  if (header->rd)
    printf("RD ");
  if (header->ra)
    printf("RA ");
  printf("\n");
  printf("question count: %i\n", header->q_count);
  printf("answer record count: %i\n", header->ans_count);
  printf("authority record count: %i\n", header->auth_count);
  printf("additional record count: %i\n", header->add_count);
}