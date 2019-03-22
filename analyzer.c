#include "sniffers/sniff_ethernet.c"
#include "sniffers/sniff_ipv4.c"
#include "sniffers/sniff_ipv6.c"
#include "sniffers/sniff_tcp.c"
#include "sniffers/sniff_udp.c"
#include "sniffers/sniff_dhcp.c"
#include "sniffers/sniff_dns.c"

#define MAXBYTES 1518
#define TIMEOUT 1000

int verbosity = 1;

// Prints an error message and exits the program.
void panic(char *message, char *errbuf)
{
  fprintf(stderr, "error:\n%s:\n%s\n", message, errbuf);
  exit(errno);
}

// Returns a printable string of the current timestamp.
char *timestamp(void)
{
  time_t now;
  char *stamp;
  char *pos;
  now = time(NULL);
  stamp = asctime(localtime(&now));
  pos = strchr(stamp, '\n');
  *pos = '\0';
  return stamp;
}

// Returns a printable string of an IP address.
char *ip_itoa(bpf_u_int32 n)
{
  struct in_addr ip;
  ip.s_addr = n;
  return inet_ntoa(ip);
}

// Prints program usage and lists options.
void print_usage(void)
{
  printf("Captures, analyzes and prints the content of network packets.\n");
  printf("Options:\n");
  printf("  -i <interface> : set interface for live analysis\n");
  printf("  -o <file_name> : set file to open for offline analysis\n");
  printf("  -f <filter> : set filter for captures\n");
  printf("  -v <1..3> : set level of verbosity (1: low, 2: medium, 3: high)\n");
  printf("If no interface or file is provided, an interface is automatically picked.\n");
  printf("If no level of verbosity is selected, verbosity is set to 1 by default.\n");
}

// Sets the verbosity level after checking the argument is valid.
// If it is not, prints program usage and exits the program.
void set_verbo(char *arg)
{
  switch (arg[0])
  {
  case '1':
  case '2':
  case '3':
    break;
  default:
    print_usage();
    panic("Unknown verbosity argument", arg);
  }

  verbosity = (arg[0] - '0');
}

// =============== GOT_PACKET FUNCTION =============== //
// pcap_loop callback. Captures packets and analyzes them.
void got_packet(unsigned char *args,
                const struct pcap_pkthdr *header,
                const unsigned char *packet)
{
  printf("[%s] New packet captured.\n", timestamp());

  // if user asked for low verbosity, end here
  if (verbosity < 2)
    return;

  // otherwise begin sniffing
  int packet_size = 0;
  int next_protocol = 0;
  unsigned short src_port;
  unsigned short dst_port;

  // read Ethernet header
  sniff_ethernet(packet, verbosity, &packet_size, &next_protocol);

  // read IP header
  switch (next_protocol)
  {
  case IPV4:
    sniff_ipv4(packet, verbosity, &packet_size, &next_protocol);
    break;
  case IPV6:
    sniff_ipv6(packet, verbosity, &packet_size, &next_protocol);
    break;
  default:
    fprintf(stderr, "   >>> unsupported protocol: %d\n\n", next_protocol);
    return;
  }

  // read packet body
  switch (next_protocol)
  {
  case TCP:
    sniff_tcp(packet, verbosity, &packet_size, &src_port, &dst_port);
    break;
  case UDP:
    sniff_udp(packet, verbosity, &packet_size, &src_port, &dst_port);
    break;
  default:
    fprintf(stderr, "   >>> unsupported protocol: %d\n\n", next_protocol);
    return;
  }

  if ((src_port == DHCPS && dst_port == DHCPD) ||
      (src_port == DHCPD && dst_port == DHCPS))
  {
    sniff_dhcp(packet, verbosity, &packet_size);
  }

  if ((src_port == DNS || dst_port == DNS))
  {
    sniff_dns(packet, verbosity, &packet_size);
  }

  printf("\n");
}

// ================== MAIN FUNCTION ================== //
// Reads arguments provided, connects to interface or opens
// the provided file, then initializes the packet capture.
int main(int argc, char **argv)
{
  printf("----- PACKET ANALYZER -----\n");
  printf("\n");

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  bpf_u_int32 net;
  bpf_u_int32 mask;
  struct bpf_program fp;

  // arguments
  int c;
  extern char *optarg;
  char *device = NULL;
  char *file = NULL;
  char *filter = NULL;

  while ((c = getopt(argc, argv, "i:o:f:v:")) != -1)
  {
    switch (c)
    {
    case 'i':
      device = optarg;
      break;
    case 'o':
      file = optarg;
      break;
    case 'f':
      filter = optarg;
      break;
    case 'v':
      set_verbo(optarg);
      break;
    default:
      print_usage();
      panic("Unknown option", "Refer to usage.");
    }
  }

  // if no argument is given, use the default device
  if (device == NULL && file == NULL)
  {
    device = pcap_lookupdev(errbuf);
    if (device == NULL)
      panic("Cannot find a default device", errbuf);
  }

  // if a device is set up, start live analysis
  if (device != NULL)
  {
    printf("Selected device: %s\n", device);
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
      panic("Cannot get netmask for device", errbuf);

    printf("> IP address: %s\n> sub-network mask: %s\n",
           ip_itoa(net), ip_itoa(mask));

    handle = pcap_open_live(device,
                            MAXBYTES,
                            1,
                            TIMEOUT,
                            errbuf);
    if (handle == NULL)
      panic("Cannot open selected device", errbuf);

    if (filter != NULL)
    {
      if (pcap_compile(handle, &fp, filter, 0, net) == -1)
        panic("Cannot compile filter", pcap_geterr(handle));
      if (pcap_setfilter(handle, &fp) == -1)
        panic("Cannot set filter", pcap_geterr(handle));
    }
  }
  // otherwise, start offline analysis
  else
  {
    handle = pcap_open_offline(file, errbuf);
    if (handle == NULL)
      panic("Cannot open file for offline analysis", errbuf);
  }

  printf("\n");
  printf("----- PACKET CAPTURES -----\n");
  printf("-- Press Ctrl+C to quit. --\n");
  printf("\n");

  if (pcap_loop(handle, -1, got_packet, NULL) < 0)
    panic("Failed to capture packets", errbuf);

  pcap_close(handle);

  return 0;
}