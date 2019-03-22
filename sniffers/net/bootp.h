/* @(#) $Header: /tcpdump/master/tcpdump/bootp.h,v 1.11 2001/01/09 07:39:13 fenner Exp $ (LBL) */
/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1048.
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 * Copyright 1988 by Carnegie Mellon.
 *
 * Permission to use, copy, modify, and distribute this program for any
 * purpose and without fee is hereby granted, provided that this copyright
 * and permission notice appear on all copies and supporting documentation,
 * the name of Carnegie Mellon not be used in advertising or publicity
 * pertaining to distribution of the program without specific prior
 * permission, and notice be given in supporting documentation that copying
 * and distribution is by permission of Carnegie Mellon and Stanford
 * University.  Carnegie Mellon makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

struct bootp
{
  unsigned char bp_op;           /* packet opcode type */
  unsigned char bp_htype;        /* hardware addr type */
  unsigned char bp_hlen;         /* hardware addr length */
  unsigned char bp_hops;         /* gateway hops */
  unsigned long bp_xid;         /* transaction ID */
  unsigned int bp_secs;        /* seconds since boot began */
  unsigned int bp_flags;       /* flags: 0x8000 is broadcast */
  struct in_addr bp_ciaddr; /* client IP address */
  struct in_addr bp_yiaddr; /* 'your' IP address */
  struct in_addr bp_siaddr; /* server IP address */
  struct in_addr bp_giaddr; /* gateway IP address */
  unsigned char bp_chaddr[16];   /* client hardware address */
  unsigned char bp_sname[64];    /* server host name */
  unsigned char bp_file[128];    /* boot file name */
  unsigned char bp_vend[64];     /* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define IPPORT_BOOTPS 67
#define IPPORT_BOOTPC 68

#define BOOTREPLY 2
#define BOOTREQUEST 1

/*
 * Vendor magic cookie (v_magic) for CMU
 */
#define VM_CMU "CMU"

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048  \
  {                 \
    99, 130, 83, 99 \
  }

/*
 * Hardware types from Assigned Numbers RFC.
 */
#define HTYPE_ETHERNET 1
#define HTYPE_EXP_ETHERNET 2
#define HTYPE_AX25 3
#define HTYPE_PRONET 4
#define HTYPE_CHAOS 5
#define HTYPE_IEEE802 6
#define HTYPE_ARCNET 7

/*
 * RFC1048 tag values used to specify what information is being supplied in
 * the vendor field of the packet.
 */

#define TAG_PAD ((unsigned char)0)
#define TAG_SUBNET_MASK ((unsigned char)1)
#define TAG_TIME_OFFSET ((unsigned char)2)
#define TAG_GATEWAY ((unsigned char)3)
#define TAG_TIME_SERVER ((unsigned char)4)
#define TAG_NAME_SERVER ((unsigned char)5)
#define TAG_DOMAIN_SERVER ((unsigned char)6)
#define TAG_LOG_SERVER ((unsigned char)7)
#define TAG_COOKIE_SERVER ((unsigned char)8)
#define TAG_LPR_SERVER ((unsigned char)9)
#define TAG_IMPRESS_SERVER ((unsigned char)10)
#define TAG_RLP_SERVER ((unsigned char)11)
#define TAG_HOSTNAME ((unsigned char)12)
#define TAG_BOOTSIZE ((unsigned char)13)
#define TAG_END ((unsigned char)255)
/* RFC1497 tags */
#define TAG_DUMPPATH ((unsigned char)14)
#define TAG_DOMAINNAME ((unsigned char)15)
#define TAG_SWAP_SERVER ((unsigned char)16)
#define TAG_ROOTPATH ((unsigned char)17)
#define TAG_EXTPATH ((unsigned char)18)
/* RFC2132 */
#define TAG_IP_FORWARD ((unsigned char)19)
#define TAG_NL_SRCRT ((unsigned char)20)
#define TAG_PFILTERS ((unsigned char)21)
#define TAG_REASS_SIZE ((unsigned char)22)
#define TAG_DEF_TTL ((unsigned char)23)
#define TAG_MTU_TIMEOUT ((unsigned char)24)
#define TAG_MTU_TABLE ((unsigned char)25)
#define TAG_INT_MTU ((unsigned char)26)
#define TAG_LOCAL_SUBNETS ((unsigned char)27)
#define TAG_BROAD_ADDR ((unsigned char)28)
#define TAG_DO_MASK_DISC ((unsigned char)29)
#define TAG_SUPPLY_MASK ((unsigned char)30)
#define TAG_DO_RDISC ((unsigned char)31)
#define TAG_RTR_SOL_ADDR ((unsigned char)32)
#define TAG_STATIC_ROUTE ((unsigned char)33)
#define TAG_USE_TRAILERS ((unsigned char)34)
#define TAG_ARP_TIMEOUT ((unsigned char)35)
#define TAG_ETH_ENCAP ((unsigned char)36)
#define TAG_TCP_TTL ((unsigned char)37)
#define TAG_TCP_KEEPALIVE ((unsigned char)38)
#define TAG_KEEPALIVE_GO ((unsigned char)39)
#define TAG_NIS_DOMAIN ((unsigned char)40)
#define TAG_NIS_SERVERS ((unsigned char)41)
#define TAG_NTP_SERVERS ((unsigned char)42)
#define TAG_VENDOR_OPTS ((unsigned char)43)
#define TAG_NETBIOS_NS ((unsigned char)44)
#define TAG_NETBIOS_DDS ((unsigned char)45)
#define TAG_NETBIOS_NODE ((unsigned char)46)
#define TAG_NETBIOS_SCOPE ((unsigned char)47)
#define TAG_XWIN_FS ((unsigned char)48)
#define TAG_XWIN_DM ((unsigned char)49)
#define TAG_NIS_P_DOMAIN ((unsigned char)64)
#define TAG_NIS_P_SERVERS ((unsigned char)65)
#define TAG_MOBILE_HOME ((unsigned char)68)
#define TAG_SMPT_SERVER ((unsigned char)69)
#define TAG_POP3_SERVER ((unsigned char)70)
#define TAG_NNTP_SERVER ((unsigned char)71)
#define TAG_WWW_SERVER ((unsigned char)72)
#define TAG_FINGER_SERVER ((unsigned char)73)
#define TAG_IRC_SERVER ((unsigned char)74)
#define TAG_STREETTALK_SRVR ((unsigned char)75)
#define TAG_STREETTALK_STDA ((unsigned char)76)
/* DHCP options */
#define TAG_REQUESTED_IP ((unsigned char)50)
#define TAG_IP_LEASE ((unsigned char)51)
#define TAG_OPT_OVERLOAD ((unsigned char)52)
#define TAG_TFTP_SERVER ((unsigned char)66)
#define TAG_BOOTFILENAME ((unsigned char)67)
#define TAG_DHCP_MESSAGE ((unsigned char)53)
#define TAG_SERVER_ID ((unsigned char)54)
#define TAG_PARM_REQUEST ((unsigned char)55)
#define TAG_MESSAGE ((unsigned char)56)
#define TAG_MAX_MSG_SIZE ((unsigned char)57)
#define TAG_RENEWAL_TIME ((unsigned char)58)
#define TAG_REBIND_TIME ((unsigned char)59)
#define TAG_VENDOR_CLASS ((unsigned char)60)
#define TAG_CLIENT_ID ((unsigned char)61)
/* RFC 2241 */
#define TAG_NDS_SERVERS ((unsigned char)85)
#define TAG_NDS_TREE_NAME ((unsigned char)86)
#define TAG_NDS_CONTEXT ((unsigned char)87)
/* RFC 2242 */
#define TAG_NDS_IPDOMAIN ((unsigned char)62)
#define TAG_NDS_IPINFO ((unsigned char)63)
/* RFC 2485 */
#define TAG_OPEN_GROUP_UAP ((unsigned char)98)
/* RFC 2563 */
#define TAG_DISABLE_AUTOCONF ((unsigned char)116)
/* RFC 2610 */
#define TAG_SLP_DA ((unsigned char)78)
#define TAG_SLP_SCOPE ((unsigned char)79)
/* RFC 2937 */
#define TAG_NS_SEARCH ((unsigned char)117)
/* RFC 3011 */
#define TAG_IP4_SUBNET_SELECT ((unsigned char)118)
/* ftp://ftp.isi.edu/.../assignments/bootp-dhcp-extensions */
#define TAG_USER_CLASS ((unsigned char)77)
#define TAG_SLP_NAMING_AUTH ((unsigned char)80)
#define TAG_CLIENT_FQDN ((unsigned char)81)
#define TAG_AGENT_CIRCUIT ((unsigned char)82)
#define TAG_AGENT_REMOTE ((unsigned char)83)
#define TAG_AGENT_MASK ((unsigned char)84)
#define TAG_TZ_STRING ((unsigned char)88)
#define TAG_FQDN_OPTION ((unsigned char)89)
#define TAG_AUTH ((unsigned char)90)
#define TAG_VINES_SERVERS ((unsigned char)91)
#define TAG_SERVER_RANK ((unsigned char)92)
#define TAG_CLIENT_ARCH ((unsigned char)93)
#define TAG_CLIENT_NDI ((unsigned char)94)
#define TAG_CLIENT_GUID ((unsigned char)97)
#define TAG_LDAP_URL ((unsigned char)95)
#define TAG_6OVER4 ((unsigned char)96)
#define TAG_PRINTER_NAME ((unsigned char)100)
#define TAG_MDHCP_SERVER ((unsigned char)101)
#define TAG_IPX_COMPAT ((unsigned char)110)
#define TAG_NETINFO_PARENT ((unsigned char)112)
#define TAG_NETINFO_PARENT_TAG ((unsigned char)113)
#define TAG_URL ((unsigned char)114)
#define TAG_FAILOVER ((unsigned char)115)
#define TAG_EXTENDED_REQUEST ((unsigned char)126)
#define TAG_EXTENDED_OPTION ((unsigned char)127)

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

/*
 * "vendor" data permitted for CMU bootp clients.
 */

struct cmu_vend
{
  unsigned char v_magic[4];           /* magic number */
  unsigned long v_flags;             /* flags/opcodes, etc. */
  struct in_addr v_smask;        /* Subnet mask */
  struct in_addr v_dgate;        /* Default gateway */
  struct in_addr v_dns1, v_dns2; /* Domain name servers */
  struct in_addr v_ins1, v_ins2; /* IEN-116 name servers */
  struct in_addr v_ts1, v_ts2;   /* Time servers */
  unsigned char v_unused[24];         /* currently unused */
};

/* v_flags values */
#define VF_SMASK 1 /* Subnet mask field contains valid data */