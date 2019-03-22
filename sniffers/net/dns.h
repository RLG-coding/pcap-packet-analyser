struct dnshdr
{
  unsigned short id;         /* identification number */
  unsigned char qr : 1;      /* query/response flag */
  unsigned char opcode : 4;  /* purpose of message */
  unsigned char aa : 1;      /* authoritive answer */
  unsigned char tc : 1;      /* truncated message */
  unsigned char rd : 1;      /* recursion desired */
  unsigned char ra : 1;      /* recursion available */
  unsigned char z : 3;       /* zero, unused */
  unsigned char rcode : 4;   /* response code */
  unsigned short q_count;    /* number of question entries */
  unsigned short ans_count;  /* number of answer entries */
  unsigned short auth_count; /* number of authority entries */
  unsigned short add_count;  /* number of resource entries */
};

struct question
{
  unsigned short qtype;
  unsigned short qclass;
};

struct response
{
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
};

struct dnsqry
{
  unsigned char *name;
  struct question *ques;
};

struct dnsrsp
{
  unsigned char *name;
  struct response *resource;
  unsigned char *rdata;
};