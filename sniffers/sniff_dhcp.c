#include "net/bootp.h"
#include "defs.h"

void print_vendor(unsigned char *vendor)
{
  int off = 4; // start after magic cookie
  unsigned char tag;
  unsigned char len;
  int i;

  while (off < 64 && tag != 255)
  {
    tag = vendor[off];
    len = vendor[off + 1];

    printf("    tag %i: ", tag);
    for (i = 0; i < len; i++)
      printf("%c", vendor[off + 2 + i]);
    printf("\n");

    off += len + 2;
  }
}

void sniff_dhcp(const unsigned char *packet, int verbosity, int *packet_size)
{
  struct bootp *header;
  unsigned char htype;
  unsigned int flags;
  unsigned char vendor[64];
  int i;

  header = (struct bootp *)(packet + *packet_size);
  *packet_size += sizeof(*header);
  htype = header->bp_htype;
  flags = header->bp_flags;

  printf("   >>> BOOTP / DHCP\n");

  // if user asked for medium verbosity, end here
  if (verbosity < 3)
    return;

  printf("operation code: ");
  if (header->bp_op = BOOTREQUEST)
    printf("1 (REQ)\n");
  else
    printf("2 (RES)\n");
  printf("hardware type: 0x%.2x ", htype);
  if (htype == HTYPE_ETHERNET)
    printf("(Ethernet)\n");
  else if (htype == HTYPE_EXP_ETHERNET)
    printf("(Experimental Ethernet)\n");
  else if (htype == HTYPE_IEEE802)
    printf("(IEEE 802)\n");
  else if (htype == HTYPE_ARCNET)
    printf("(ARCNET)\n");
  else
    printf("(unknown)\n");
  printf("hardware address len: %i\n", header->bp_hlen);
  printf("hops: %i\n", header->bp_hops);
  printf("transaction identifier: 0x%.8x\n", ntohl(header->bp_xid));
  printf("seconds: %i\n", ntohs(header->bp_secs));
  printf("flags: ");
  if (flags & 0x8000)
    printf("BROADCAST\n");
  else
    printf("UNICAST\n");
  printf("client IP address: %s\n", inet_ntoa(header->bp_ciaddr));
  printf("your IP address: %s\n", inet_ntoa(header->bp_yiaddr));
  printf("server IP address: %s\n", inet_ntoa(header->bp_siaddr));
  printf("gateway IP address: %s\n", inet_ntoa(header->bp_giaddr));
  printf("client hardware address: ");
  for (i = 0; i < 5; i++)
    printf("%.2x:", header->bp_chaddr[i]);
  printf("%.2x\n", header->bp_chaddr[5]);
  printf("server name: ");
  if (header->bp_sname[0] != '\0')
    printf("\"%s\"\n", header->bp_sname);
  else
    printf("NONE\n");
  printf("boot file name: ");
  if (header->bp_sname[0] != '\0')
    printf("\"%s\"\n", header->bp_sname);
  else
    printf("NONE\n");

  printf("vendor-specific area:\n");
  if (vendor[0] != 99 || vendor[1] != 130 || vendor[2] != 83 || vendor[3] != 99)
    printf("    failed magic cookie test\n");
  else
    print_vendor(vendor);
}