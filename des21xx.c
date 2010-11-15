/*-
 * Copyright (c) 2010 Alexey Illarionov <littlesavage@rambler.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _GNU_SOURCE

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

const char *progname = "des21xx";
const char *revision = "$Revision: 0.2 $";

#define DEFAULT_TIMEOUT 3000
#define DEFAULT_SCAN_TIMEOUT 3000

#define DST_BROADCAST_SERVNAME "64515"
#define DST_BROADCAST_PORT 64515

#define DST_MULTICAST_PORT 64515
#define DST_MULTICAST_ADDR "239.255.255.100"

#define TFTP_PORT 69
#define TFTP_RESEND_CNT 3
#define TFTP_TIMEOUT 10000

#define TFTP_OPCODE_RRQ 1
#define TFTP_OPCODE_WRQ 2
#define TFTP_OPCODE_DATA 3
#define TFTP_OPCODE_ACK  4
#define TFTP_OPCODE_ERROR 5

enum attr_code_t {
   ATTR_PRODUCT_NAME    = 0x0001,
   ATTR_SYSTEM_NAME     = 0x0002,
   ATTR_SYSTEM_LOCATION = 0x0003,
   ATTR_IP              = 0x0004,
   ATTR_NETMASK         = 0x0005,
   ATTR_GW              = 0x0006,
   ATTR_TRAP_IP         = 0x0007,
   ATTR_NEW_PASSWORD    = 0x0008,
   ATTR_PASSWORD        = 0x0009,
   ATTR_USE_DHCP        = 0x000a,
   ATTR_FIRMWARE        = 0x000b,
   ATTR_WEB_PORT        = 0x0015,
   ATTR_GROUP_INTERVAL  = 0x0016,
   ATTR_UNKNOWN81       = 0x0081
};

struct switch_pkt_hdr_t {
   uint16_t header; /* 0x0002 */
   uint16_t is_answer;
   uint8_t  mac[6];
   /* 0x0003, 0x0002 */
   uint16_t proto_subversion;
   /*  0001 - discovery
    *  0002 - discovery response
    *  0005 - info
    *  0006 - info response
    *  0007 - change config,
    *  0008 - change config response
    *  0009 - trap for smart console
    *  000a - upgrade firmware,
    *  000b - upgrade firmware response,
    */
   uint16_t cmd;
   uint16_t err_code; /* 0000 = ok, 2- error */
   uint32_t unkown_01945ae0; /* 01945ae0  */
   uint8_t  dst_mac[6];
   uint16_t unk1;
   uint16_t padd[6];
   uint8_t data[];
};

struct switch_pkt_t {
   union {
      struct switch_pkt_hdr_t hdr;
      uint8_t p[1000];
   } data;
   size_t pkt_size;
};

struct switch_t {
   uint8_t mac[6];
   uint8_t dst_mac[6];
   unsigned proto_subversion;

   char product_name[41];
   char system_name[21];
   char system_location[21];
   struct in_addr ip;
   struct in_addr netmask;
   struct in_addr gw;
   struct in_addr trap_ip;
   int use_dhcp;
   int web_port;
   int group_interval;
   char firmware[9];
   unsigned is_error;
   char err_msg[120];
};


int set_sw_err(struct switch_t *res, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(res->err_msg, sizeof(res->err_msg), fmt, ap);
   res->err_msg[sizeof(res->err_msg)-1]='\0';
   res->is_error=1;
   va_end(ap);
   return -1;
}

void strcpy_trim(char *dst_p, size_t dst_size, const uint8_t *src, size_t src_strlen)
{
   unsigned i;
   unsigned trim_p;
   unsigned last;
   unsigned char *dst_up = (unsigned char *)dst_p;

   if (!src_strlen)
      return;

   last = (dst_size >= src_strlen ? dst_size-1 : src_strlen);
   trim_p=last;

   for (i=0; i<last; i++) {
      dst_up[i]=src[i];
      if (isspace(src[i]) || (src[i]=='\0')){
	 if (trim_p==last)
	    trim_p=i;
      }else {
	 trim_p=last;
      }
   }
   dst_up[trim_p]='\0';
}


int load_switch(const void *pkt, size_t pkt_size, struct switch_t *res)
{
   const uint8_t *p;
   unsigned left;
   const struct switch_pkt_hdr_t *sw_pkt;
   unsigned i;

   if (!pkt || !res || !pkt_size)
      return -1;

   sw_pkt = (const struct switch_pkt_hdr_t *)pkt;

   if (pkt_size < sizeof(struct switch_pkt_hdr_t))
      return set_sw_err(res, "packet too short");

   if (sw_pkt->header != htons((uint16_t)2))
      return set_sw_err(res, "wrong packet `proto` parameter: %4x", sw_pkt->header);

   if (sw_pkt->is_answer != htons(1))
      return set_sw_err(res, "wrong packet `is_answer` parameter: %4x", sw_pkt->is_answer);

   /* XXX: cmd, err_code  */

   if (sw_pkt->unkown_01945ae0 != htonl((uint32_t)0x01945ae0))
      return set_sw_err(res, "wrong packet id: %8x (should be 0x01945ae0)",
	    sw_pkt->unkown_01945ae0);

   for (i=0; i<6; i++) { res->mac[i]=sw_pkt->mac[i]; };
   for (i=0; i<6; i++) { res->dst_mac[i]=sw_pkt->dst_mac[i]; };

   res->proto_subversion = ntohs(sw_pkt->proto_subversion);

   res->product_name[0]='\0';
   res->system_name[0]='\0';
   res->system_location[0]='\0';
   res->ip.s_addr=0;
   res->netmask.s_addr=0;
   res->gw.s_addr=0;
   res->trap_ip.s_addr=0;
   res->use_dhcp=-1;
   res->web_port=-1;
   res->group_interval=-1;
   res->firmware[0]='\0';

   p = sw_pkt->data;
   left = pkt_size-sizeof(*sw_pkt);

   while (left > 0) {
      unsigned code;
      unsigned attr_size;

      if (left  < 4)
	 return set_sw_err(res, "Truncated packet ");

      code = (p[0] << 8) | p[1];
      attr_size = (p[2] << 8) | p[3];

      if (attr_size < 4)
	 return set_sw_err(res, "Truncated packet: wrong attribute size");

      if (attr_size > left)
	 return set_sw_err(res, "Truncated packet: too long attribute");

      p += 4;
      left -= 4;
      attr_size -= 4;

      switch (code) {
	 case ATTR_PRODUCT_NAME : /* product_name 0001002c  */
	    strcpy_trim(res->product_name, sizeof(res->product_name),
		  p, attr_size);
	    break;
	 case ATTR_SYSTEM_NAME: /* system_name  00020018 */
	    strcpy_trim(res->system_name, sizeof(res->system_name),
		  p, attr_size);
	    break;
	 case ATTR_SYSTEM_LOCATION: /* system_location 00030018 */
	    strcpy_trim(res->system_location, sizeof(res->system_location),
		  p, attr_size);
	    break;
	 case ATTR_IP: /* switch_ip 00040008 */
	    if (attr_size != 4)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "ip_address", attr_size, 4);
	    res->ip.s_addr = *(uint32_t *)p;
	    break;
	 case ATTR_NETMASK: /* switch_netmask 00050008 */
	    if (attr_size != 4)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "switch_netmask", attr_size, 4);
	    res->netmask.s_addr = *(uint32_t *)p;
	    break;
	 case ATTR_GW: /* switch gw 00060008 */
	    if (attr_size != 4)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "switch_gateway", attr_size, 4);
	    res->gw.s_addr = *(uint32_t *)p;
	    break;
	 case ATTR_TRAP_IP: /* switch trap ip 00060008 */
	    if (attr_size != 4)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "trap_ip", attr_size, 4);
	    res->trap_ip.s_addr = *(uint32_t *)p;
	    break;

	 case ATTR_USE_DHCP: /* use dhcp  */
	    if (attr_size != 2)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "use_dhcp", attr_size, 2);
	    res->use_dhcp = (p[0] | p[1]) ? 1 : 0;
	    break;
	 case ATTR_WEB_PORT: /* web port ?  0015 0006 0050 */
	    if (attr_size != 2)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "web_port", attr_size, 2);
	    res->web_port = ntohs(*(uint16_t *)p);
	    break;
	 case ATTR_GROUP_INTERVAL: /* group_interval 0016 0008 0000 0078 */
	    if (attr_size != 4)
	       return set_sw_err(res, "Wrong `%s` attribute length: %x (should be %x)", 
		     "group_interval", attr_size, 4);
	    res->group_interval = ntohl(*(uint32_t *)p);
	    break;

	 case ATTR_FIRMWARE: /* firmware 000b 000c  */
	    strcpy_trim(res->firmware, sizeof(res->firmware),
		  p, attr_size);
	    break;
	 case ATTR_UNKNOWN81: /* ? 0081 0014 0033 0fff 0000 0000 0000 0000 2000 0000  */
	 default:
	    break;
      }

      left -= attr_size;
      p = p + attr_size;
   }

   assert(left==0);

   res->is_error=0;
   res->err_msg[0]='\0';

   return 0;
}

void fprintsw(FILE *s, const struct switch_t *sw, int verbose)
{
   char ip[INET_ADDRSTRLEN];
   char netmask[INET_ADDRSTRLEN];
   char mac[18];

   if (!sw)
      return;

   inet_ntop(AF_INET, &sw->ip, ip, sizeof(ip));
   inet_ntop(AF_INET, &sw->netmask, netmask, sizeof(ip));
   sprintf(mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	  sw->mac[0],sw->mac[1],sw->mac[2],sw->mac[3],sw->mac[4],sw->mac[5]);

   switch (verbose) {
      case 0:
	 fprintf(s,
	       "%-9s %-15s %-15s %-17s %-10s %-10s %03d %s\n",
	       sw->product_name,
	       ip,
	       netmask,
	       mac,
	       sw->system_name,
	       sw->system_location,
	       sw->proto_subversion,
	       sw->firmware
	       );
	 break;
      case 100:
	 {
	    char gateway[INET_ADDRSTRLEN];
	    char trap_ip[INET_ADDRSTRLEN];
	    char dst_mac[18];

	    inet_ntop(AF_INET, &sw->gw, gateway, sizeof(gateway));
	    inet_ntop(AF_INET, &sw->trap_ip, trap_ip, sizeof(trap_ip));
	    sprintf(dst_mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		  sw->dst_mac[0],sw->dst_mac[1],sw->dst_mac[2],
		  sw->dst_mac[3],sw->dst_mac[4],sw->dst_mac[5]);

	    fprintf(s,
		  "Switch:          %s\n"
		  "System name:     %s\n"
		  "System location: %s\n"
		  "Protocol:        2.001.%03d\n"
		  "DHCP:            %s\n"
		  "IP:              %s\n"
		  "Netmask:         %s\n"
		  "Gateway:         %s\n"
		  "Trap IP:         %s\n"
		  "MAC:             %s\n"
		  "Firmware:        %s\n"
		  "Group Interval:  %i\n"
		  "Our MAC:         %s\n",
		  sw->product_name,
		  sw->system_name,
		  sw->system_location,
		  sw->proto_subversion,
		  (sw->use_dhcp ? "enabled" : "disabled"),
		  ip,
		  netmask,
		  gateway,
		  trap_ip,
		  mac,
		  sw->firmware,
		  sw->group_interval == -1 ? 0 : sw->group_interval,
		  dst_mac
		  );
	 }
	 break;
      default:
	 assert(0);
	 break;
   }

}

void pkt_init_hdr(struct switch_pkt_hdr_t *pkt, unsigned cmd)
{
   bzero(pkt, sizeof(*pkt));

   pkt->header = htons(2);
   pkt->cmd = htons(cmd);
   pkt->unkown_01945ae0 = htonl(0x01945ae0);
}

void pkt_init(struct switch_pkt_t *pkt, unsigned cmd)
{
   pkt_init_hdr(&pkt->data.hdr, cmd);
   pkt->pkt_size=sizeof(pkt->data.hdr);
}

void pkt_add_attr(struct switch_pkt_t *pkt,
      int attr_code, const void *buf, int size)
{
   uint8_t *p;

   assert(pkt->pkt_size+size+4 < sizeof(pkt->data));

   p = &pkt->data.p[pkt->pkt_size];

   *(uint16_t *)p = htons((uint16_t)attr_code);
   p += 2;
   *(uint16_t *)p = htons((uint16_t)size+4);
   p += 2;
   if (size)
      memcpy(p, buf, size);
   pkt->pkt_size = pkt->pkt_size + size + 4;
}


int get_iface_addr(const char *iface, struct in_addr *addr, struct in_addr *broadaddr)
{

   struct ifreq req;
   int s;

   bzero(&req, sizeof(req));

   strncpy(req.ifr_name, iface, sizeof(req.ifr_name)-1);
   req.ifr_name[sizeof(req.ifr_name)-1]='\0';

   s = socket(AF_INET, SOCK_DGRAM, 0);

   if (!s)
      return 0;

   if (ioctl(s, SIOCGIFADDR, &req) == -1) {
      close(s);
      return 0;
   }
   addr->s_addr = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr.s_addr;

   if (broadaddr) {
      if (ioctl(s, SIOCGIFBRDADDR, &req) == -1) {
	 close(s);
	 return 0;
      }
      broadaddr->s_addr = ((struct sockaddr_in *)&req.ifr_broadaddr)->sin_addr.s_addr;
   }

   close(s);

   return 1;
}

int init_multicast_socket(const char *ifname)
{
   const int on = 1;
   const int off = 0;
   int s;
   struct group_req req;
   struct ip_mreqn ifaddr;
   struct sockaddr_in *addr;

   s = socket(AF_INET, SOCK_DGRAM, 0);

   if (!s)
      return -1;

   if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
      close(s);
      return -1;
   }

   bzero(&req, sizeof(req));
   bzero(&ifaddr, sizeof(ifaddr));

   if (ifname && ifname[0]) {
      req.gr_interface = if_nametoindex(ifname);
      if (req.gr_interface == 0) {
	 close(s);
	 errno = ENXIO;
	 return -1;
      }
   }else {
      req.gr_interface=0;
   }

   addr = (struct sockaddr_in *)&req.gr_group;

   addr->sin_family=AF_INET;
   inet_pton(AF_INET, DST_MULTICAST_ADDR, &addr->sin_addr);
   addr->sin_port=htons(DST_MULTICAST_PORT);
#ifndef __linux__
   ((struct sockaddr *)&req.gr_group)->sa_len=sizeof(struct sockaddr_in);
#endif

   ifaddr.imr_multiaddr.s_addr=addr->sin_addr.s_addr;
   ifaddr.imr_address.s_addr=htonl(INADDR_ANY);
   ifaddr.imr_ifindex=req.gr_interface;

   if (setsockopt(s, IPPROTO_IP, MCAST_JOIN_GROUP, &req, sizeof(req)) < 0) {
      close(s);
      return -1;
   }

   if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off)) < 0) {
      close(s);
      return -1;
   }

   if (ifname && ifname[0]) {
      if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)) < 0) {
	 close(s);
	 return -1;
      }
   }

   return s;
}

int init_broadcast_socket(const char *ifname)
{
   const int on = 1;
   int s;

   s = socket(AF_INET, SOCK_DGRAM, 0);

   if (ifname) {};

   if (!s)
      return -1;

   if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
      close(s);
      return -1;
   }
#ifdef IP_ONESBCAST
   if (setsockopt(s, IPPROTO_IP, IP_ONESBCAST, &on, sizeof(on)) < 0) {
      close(s);
      return -1;
   }
#endif
#ifdef SO_BINDTODEVICE
   if (ifname[0]) {
      if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
	 close(s);
	 return -1;
      }
   }
#endif


   return s;
}

int init_unicast_socket(struct sockaddr_in *sw_addr,
      int timeout,
      int bind_to_port,
      char *err_msg,
      size_t err_msg_size)
{
   const int on = 1;
   int s;

   s = socket(AF_INET, SOCK_DGRAM, 0);

   if (!s) {
      snprintf(err_msg, err_msg_size, "Cannot create broadcast socket: %s", strerror(errno));
      return -1;
   }

   if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
      snprintf(err_msg, err_msg_size,
	    "Cannot set SO_REUSEADDR Socket option : %s", strerror(errno));
      close(s);
      return -1;
   }

   if (timeout) {
      struct timeval tv;

      tv.tv_sec = timeout/1000;
      tv.tv_usec = 1000 * (timeout % 1000);

      if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
	 snprintf(err_msg, err_msg_size,
	       "Cannot set SO_RCVTIMEO Socket option: %s", strerror(errno));
	 close(s);
	 return -1;
      }
      if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
	 snprintf(err_msg, err_msg_size,
	       "Cannot set SO_SNDTIMEO Socket option: %s", strerror(errno));
	 close(s);
	 return -1;
      }
   }

   if (bind_to_port) {
      struct sockaddr_in  bind_addr;

      bzero(&bind_addr, sizeof(bind_addr));
      bind_addr.sin_family = AF_INET;
      bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      bind_addr.sin_port = htons(bind_to_port);

      if (bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
	 snprintf(err_msg, err_msg_size, "Cannot bind to addr: %s", strerror(errno));
	 close(s);
	 return -1;
      }
   }

   if (connect(s, (const struct sockaddr *)sw_addr, sizeof(*sw_addr)) < 0) {
      snprintf(err_msg, err_msg_size,
	    "Cannot connect to switch: %s", strerror(errno));
      close(s);
      return -1;
   }

   return s;
}

int discovery(const char *ifname, int timeout)
{
   int s_broadcast, s_multicast;
   struct sockaddr_in dst_broadcast, dst_multicast;
   struct in_addr iface_addr, iface_broadaddr;
   struct switch_pkt_hdr_t discovery_pkt;
   struct timespec end_time;
   fd_set readfds;
   int maxfd;
   int res = 0;

   fprintf(stdout, "Scaning for switches");
   if (ifname && ifname[0]) {
      fprintf(stdout, " on interface `%s`", ifname);
   }

   if (timeout) {
      fprintf(stdout, ", timeout: %us\n", timeout/1000);
   }else {
      fprintf(stdout, "\n");
   }

   if (ifname[0]) {
      if (get_iface_addr(ifname, &iface_addr, &iface_broadaddr) <= 0) {
	 perror("Wrong interface");
	 return -1;
      }
   }else {
      iface_addr.s_addr=htonl(INADDR_ANY);
      iface_broadaddr.s_addr=htonl(INADDR_BROADCAST);
   }


   /* Create sockets  */
   s_broadcast = init_broadcast_socket(ifname);
   if (s_broadcast < 0) {
      perror("Cannot create broadcast socket");
      return -1;
   }

   s_multicast = init_multicast_socket(ifname);
   if (s_multicast < 0) {
      perror("Cannot create multicast socket");
      close(s_broadcast);
      return -1;
   }

   /* destination sockaddr  */
   bzero(&dst_broadcast, sizeof(dst_broadcast));
   dst_broadcast.sin_family = AF_INET;
   dst_broadcast.sin_port = htons(DST_BROADCAST_PORT);
   dst_broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
#ifdef IP_ONESBCAST
   if (ifname[0])
      dst_broadcast.sin_addr.s_addr = iface_broadaddr.s_addr;
#endif

   bzero(&dst_multicast, sizeof(dst_multicast));
   dst_multicast.sin_family = AF_INET;
   dst_multicast.sin_port = htons(DST_MULTICAST_PORT);
   inet_pton(AF_INET, DST_MULTICAST_ADDR, &dst_multicast.sin_addr);

   /* Send discovery packet  */
   pkt_init_hdr(&discovery_pkt, 1);

   if (sendto(s_broadcast, &discovery_pkt, sizeof(discovery_pkt), 0,
	    (const struct sockaddr *)&dst_broadcast, sizeof(dst_broadcast)) < 0) {
      perror("Cannot send broadcast packet");
      close(s_broadcast);
      close(s_multicast);
      return -1;
   }

   if (sendto(s_multicast, &discovery_pkt, sizeof(discovery_pkt), 0,
	    (const struct sockaddr *)&dst_multicast, sizeof(dst_multicast)) < 0) {
      perror("Cannot send multicast packet");
      close(s_broadcast);
      close(s_multicast);
      return -1;
   }

   /* Receive */

   FD_ZERO(&readfds);
   maxfd = (s_broadcast > s_multicast ? s_broadcast : s_multicast) + 1;

   if (timeout) {
      clock_gettime(CLOCK_MONOTONIC, &end_time);
      end_time.tv_sec += timeout / 1000;
      end_time.tv_nsec += 1000000 * (timeout % 1000);
   }

   for(;;) {
      int n;
      struct timespec cur_time;
      struct timeval tmout;

      if (timeout) {
	 clock_gettime(CLOCK_MONOTONIC, &cur_time);
	 if ((cur_time.tv_sec > end_time.tv_sec)
	       || ((cur_time.tv_sec == end_time.tv_sec)
		  && (cur_time.tv_nsec >= end_time.tv_nsec))) {
	    /* timeout. */
	    break;
	 }
	 tmout.tv_sec = end_time.tv_sec - cur_time.tv_sec;
	 tmout.tv_usec = tmout.tv_sec == 0 ? (end_time.tv_nsec - cur_time.tv_nsec)/1000 : 0;

	 assert(tmout.tv_sec>=0);
	 assert(tmout.tv_usec>=0);
      }

      FD_ZERO(&readfds);
      FD_SET(s_broadcast, &readfds);
      FD_SET(s_multicast, &readfds);

      if ((n = select(maxfd, &readfds, NULL, NULL, timeout == 0 ? NULL : &tmout)) < 0) {
	 if (errno == EINTR)
	    continue;
	 else {
	    perror("select error");
	    res = -1;
	    break;
	 }
      }

      if (FD_ISSET(s_multicast, &readfds)) {
	 ssize_t recv_len;
	 struct switch_t sw;
	 uint8_t buf[1500];

	 recv_len=recv(s_multicast, buf, sizeof(buf), 0);
	 if (recv_len < 0) {
	    perror("recv error");
	    res = -1;
	    break;
	 }else if (recv_len != 0) {
	    if (load_switch(buf, recv_len, &sw) < 0) {
	       fprintf(stderr, "cannot parse switch: %s\n", sw.err_msg);
	    }else {
	       fprintsw(stdout, &sw, 0);
	    }
	 }
      }

      if (FD_ISSET(s_broadcast, &readfds)) {
	 ssize_t recv_len;
	 struct switch_t sw;
	 uint8_t buf[1500];

	 /* XXX */
	 recv_len=recv(s_broadcast, buf, sizeof(buf), 0);
	 if (recv_len < 0) {
	    perror("recv error");
	    res = -1;
	    break;
	 }else if (recv_len != 0) {
	    if (load_switch(buf, recv_len, &sw) < 0) {
	       fprintf(stderr, "cannot parse switch: %s\n", sw.err_msg);
	    }else {
	       fprintsw(stdout, &sw, 0);
	    }
	 }
      }
   }

   close(s_broadcast);
   close(s_multicast);

   return res;
}

int send_n_recv(struct sockaddr_in *sw_addr, int timeout,
      struct switch_pkt_t *pkt,
      void *recv_buf, size_t recv_buf_size)
{
   int s;
   ssize_t recv_len;
   char err_msg[120];

   s = init_unicast_socket(sw_addr, timeout, 0, err_msg, sizeof(err_msg));
   if (!s) {
      fprintf(stderr, "%s\n", err_msg);
      return -1;
   }

   /* send req */
   if (send(s, &pkt->data, pkt->pkt_size,0) < 0) {
      perror("Cannot send packet to switch");
      close(s);
      return -1;
   }

   /* recv */
   recv_len=recv(s,
	 recv_buf, recv_buf_size, 0);
   if (recv_len < 0) {
      perror(NULL);
      close(s);
      return -1;
   }else if (recv_len == 0) {
      fprintf(stderr, "no data");
      close(s);
      return -1;
   }

   close(s);

   return recv_len;
}


int show(struct sockaddr_in *sw_addr, int timeout)
{
   struct switch_t sw;
   struct switch_pkt_t pkt, pkt_res;
   int recv_len;
   char err_msg[120];

   pkt_init(&pkt, 5);

   if ((recv_len = send_n_recv(sw_addr, timeout, &pkt, pkt_res.data.p, sizeof(pkt_res.data.p))) <= 0)
      return -1;

   if (load_switch(pkt_res.data.p, recv_len, &sw) < 0) {
      fprintf(stderr, "cannot load switch info: %s\n", sw.err_msg);
      return -1;
   }

   fprintsw(stdout, &sw, 100);

   return 0;
}

int single_cmd(struct sockaddr_in *sw_addr, int timeout, struct switch_pkt_t *pkt)
{
   ssize_t recv_len;
   struct switch_pkt_t pkt_res;

   if (send_n_recv(sw_addr, timeout, pkt, pkt_res.data.p, sizeof(pkt_res.data)) <= 0)
      return -1;

   if (pkt_res.data.hdr.err_code) {
      fprintf(stderr, "Switch error code: %u\n", ntohs(pkt_res.data.hdr.err_code));
      return -1*ntohs(pkt_res.data.hdr.err_code);
   }else {
      fprintf(stderr, "OK\n");
   }

   return 0;
}

int config_ipif_dhcp(struct sockaddr_in *sw_addr, int timeout, char *password)
{
   const uint16_t use_dhcp=htons(1);
   struct switch_pkt_t pkt;
   char str[INET_ADDRSTRLEN];

   assert((strlen(password) < 20));

   inet_ntop(AF_INET, &sw_addr->sin_addr, str, sizeof(str));
   fprintf(stdout, "switch %s config ipif dhcp\n", str);

   pkt_init(&pkt, 7);
   pkt_add_attr(&pkt, ATTR_PASSWORD, password, strlen(password));
   pkt_add_attr(&pkt, ATTR_USE_DHCP, &use_dhcp, 2);

   return single_cmd(sw_addr, timeout, &pkt);
}

int config_ipif_staticip(struct sockaddr_in *sw_addr,
      int timeout, char *password,
      struct in_addr ip,
      struct in_addr mask,
      struct in_addr gw
      )
{
   const uint16_t do_not_use_dhcp=0;
   struct switch_pkt_t pkt;
   char sw_ip[INET_ADDRSTRLEN];
   char new_ip[INET_ADDRSTRLEN];
   char new_mask[INET_ADDRSTRLEN];
   char new_gw[INET_ADDRSTRLEN];

   assert((strlen(password) < 20));

   inet_ntop(AF_INET, &sw_addr->sin_addr, sw_ip, sizeof(sw_ip));
   inet_ntop(AF_INET, &ip, new_ip, sizeof(new_ip));
   inet_ntop(AF_INET, &mask, new_mask, sizeof(new_mask));
   inet_ntop(AF_INET, &gw, new_gw, sizeof(new_gw));

   fprintf(stdout, "switch %s config ipif %s/%s gw %s\n", sw_ip, new_ip, new_mask, new_gw);

   pkt_init(&pkt, 7);
   pkt_add_attr(&pkt, ATTR_PASSWORD, password, strlen(password));
   pkt_add_attr(&pkt, ATTR_USE_DHCP, &do_not_use_dhcp, 2);
   pkt_add_attr(&pkt, ATTR_IP, &ip, 4);
   pkt_add_attr(&pkt, ATTR_NETMASK, &mask, 4);
   pkt_add_attr(&pkt, ATTR_GW, &gw, 4);

   /* XXX */
   return single_cmd(sw_addr, timeout, &pkt);
}


int passwd(struct sockaddr_in *sw_addr, int timeout, const char *password,
      const char *new_password)
{
   struct switch_pkt_t pkt;

   char str[INET_ADDRSTRLEN];

   assert((strlen(password) < 20));
   assert((strlen(new_password) < 20));

   inet_ntop(AF_INET, &sw_addr->sin_addr, str, sizeof(str));
   fprintf(stdout, "switch %s passwd\n", str);

   pkt_init(&pkt, 7);
   pkt_add_attr(&pkt, ATTR_PASSWORD, password, strlen(password));
   pkt_add_attr(&pkt, ATTR_NEW_PASSWORD, new_password, strlen(new_password));

   return single_cmd(sw_addr, timeout, &pkt);
}

int config_nameloc(struct sockaddr_in *sw_addr, int timeout,
      const char *password,
      const char *system_name, const char *system_location)
{
   struct switch_pkt_t pkt;

   char str[INET_ADDRSTRLEN];

   inet_ntop(AF_INET, &sw_addr->sin_addr, str, sizeof(str));
   fprintf(stdout, "switch %s nameloc %s %s\n", str, system_name, system_location);

   pkt_init(&pkt, 7);
   pkt_add_attr(&pkt, ATTR_PASSWORD, password, strlen(password));
   pkt_add_attr(&pkt, ATTR_SYSTEM_NAME, system_name, strlen(system_name));
   pkt_add_attr(&pkt, ATTR_SYSTEM_LOCATION, system_location, strlen(system_location));

   return single_cmd(sw_addr, timeout, &pkt);
}

int fwupgrade(struct sockaddr_in *sw_addr, int timeout,
      const char *password,
      char *fw_name)
{
   int res;
   int s, f;
   int resend_cnt;
   char *file_basename;
   unsigned num;
   ssize_t send_len, recv_len;
   struct switch_pkt_t pkt, pkt_res;
   struct sockaddr_in tftp_addr;
   struct timespec last_report_time;
   char str[200];

   union {
      struct {
	 uint16_t opcode;
	 uint16_t num;
	 uint8_t data[512];
      } data_pkt;
      struct {
	 uint16_t opcode;
	 uint8_t data[514];
      } wrq_pkt;
      uint8_t p[516];
   } send_buf;

   union {
      struct {
	 uint16_t opcode;
	 uint16_t num;
      } ack_pkt;
      struct {
	 uint16_t opcode;
	 uint16_t err_code;
	 uint8_t err_msg[200];
      } err_pkt;
      uint8_t p[204];
   } recv_buf;

   res = -1;

   inet_ntop(AF_INET, &sw_addr->sin_addr, str, sizeof(str));
   fprintf(stdout, "switch %s fwupgrade %s\n", str, fw_name);

   file_basename = basename(fw_name);
   if (!file_basename || file_basename[0] == '\0') {
      fprintf(stderr, "wrong filename");
      return -1;
   }

   /* Init WRQ request  */
   {
      char *p, *p0;
      send_buf.wrq_pkt.opcode=htons(TFTP_OPCODE_WRQ);
#ifdef stpncpy
      p = stpncpy((char *)send_buf.wrq_pkt.data, file_basename, sizeof(send_buf.wrq_pkt.data));
#else
      p = stpcpy((char *)send_buf.wrq_pkt.data, file_basename);
#endif
      p += 1;
      if ( (uint8_t *)p + sizeof("octet") >= &send_buf.wrq_pkt.data[sizeof(send_buf.wrq_pkt.data)]) {
	 fprintf(stderr, "file name too long\n");
	 return -1;
      }
      p0 = stpcpy(p, "octet");
      send_len = (uint8_t *)p0 - send_buf.wrq_pkt.data + sizeof(send_buf.wrq_pkt.opcode)+1;
   }


   /* init tftp socket  */
   memcpy(&tftp_addr, sw_addr, sizeof(tftp_addr));
   tftp_addr.sin_port = htons(TFTP_PORT);

   s = init_unicast_socket(&tftp_addr, timeout, 0, str, sizeof(str));
   if (s < 0) {
      fprintf(stderr, "cannot create tftp socket\n");
      return -1;
   }

   /* firmware file  */
   if ( (f = open(fw_name, O_RDONLY)) < 0) {
      fprintf(stderr, "cannot open file %s\n", fw_name);
      close(s);
      return -1;
   }

   /* Get MAC address */
   pkt_init(&pkt, 5);
   if ((recv_len = send_n_recv(sw_addr, timeout, &pkt, pkt_res.data.p, sizeof(pkt_res.data.p))) <= 0)
      return -1;

   /* send `upgrade firmware` request  */
   fprintf(stdout, "Sending firmware upgrade command..\n");
   pkt_init(&pkt, 0x0a);
   /* pkt.data.hdr.unk1=htons(2); */
   memcpy(pkt.data.hdr.mac, pkt_res.data.hdr.mac, sizeof(pkt.data.hdr.dst_mac));
   pkt_add_attr(&pkt, ATTR_PASSWORD, password, strlen(password));

   if ((res = single_cmd(sw_addr, timeout, &pkt)) < 0) {
      /* if (res != -4) parameters error. Try to connect to TFTP anyway */
	 goto fwupgrade_error;
   }else
      res = -1;


   /* send firmware by tftp */
   fprintf(stdout, "Uploading firmware...\n");

   sleep(3);

   clock_gettime(CLOCK_MONOTONIC, &last_report_time);

   {
      struct timeval tmout;
      fd_set fds;
      int nfds;

      for (resend_cnt=0; ; resend_cnt++) {
	 /* WRQ  */
	 if (send(s, send_buf.p, send_len,0) < 0) {
	    perror("Cannot send WRQ packet");
	    goto fwupgrade_error;
	 }


	 /* recv wrq ack */
	 FD_ZERO(&fds);
	 FD_SET(s, &fds);

	 tmout.tv_sec = TFTP_TIMEOUT/1000;;
	 tmout.tv_usec = 1000*(TFTP_TIMEOUT % 1000);

	 nfds = select(s+1, &fds, NULL, NULL, &tmout);
	 if (nfds < 0) {
	    perror("Error waiting for TFTP WRQ ACK");
	    goto fwupgrade_error;
	 }else if (nfds == 0) {
	    if (resend_cnt < TFTP_RESEND_CNT)
	       /* resend WRQ */
	       continue;
	    else {
	       fprintf(stderr, "Timeout while waiting for TFTP WRQ ACK\n");
	       goto fwupgrade_error;
	    }
	 }else
	    break;
      }

      assert(FD_ISSET(s, &fds));
      recv_len = recv(s, recv_buf.p, sizeof(recv_buf.p), 0);
      if (recv_len < 0) {
	 perror("Recv error on TFTP WRQ ACK");
	 goto fwupgrade_error;
      }else if (recv_len < 4) {
	 fprintf(stderr, "Received short WRQ ACK: %i bytes\n", (int)recv_len);
	 goto fwupgrade_error;
      }

      if (recv_buf.err_pkt.opcode == htons(TFTP_OPCODE_ERROR)) {
	 recv_buf.err_pkt.err_msg[sizeof(recv_buf.err_pkt.err_msg)-1]='\0';
	 fprintf(stderr, "TFTP error %u: %s\n",
	       ntohs(recv_buf.err_pkt.err_code), recv_buf.err_pkt.err_msg);
	 goto fwupgrade_error;
      }else if ((recv_buf.ack_pkt.opcode != htons(TFTP_OPCODE_ACK))
	    /*   || (recv_buf.ack_pkt.num != 0) */) {
	 fprintf(stderr, "Recived wrong WRQ ack: opcode: %u pkt_num: %u size: %i\n",
	       ntohs(recv_buf.ack_pkt.opcode), ntohs(recv_buf.ack_pkt.num), (int)recv_len);
	 goto fwupgrade_error;
      }
   }

   /* send data  */
   send_buf.data_pkt.opcode = htons(TFTP_OPCODE_DATA);

   for (num=1; ; num++) {
      ssize_t read_len;
      int ack_recvd, pkt_sended;

      send_buf.data_pkt.num = htons(num);

      read_len = read(f, send_buf.data_pkt.data, sizeof(send_buf.data_pkt.data));

      if (read_len < 0) {
	 /* XXX: signals  */
	 perror("Cannor read firmware file");
	 goto fwupgrade_error;
      }else if (read_len == 0) {
	 /* XXX: send zero-byte TFTP data packet?  */
	 break;
      }

      pkt_sended = ack_recvd = 0;

      for (resend_cnt=0; resend_cnt < TFTP_RESEND_CNT; resend_cnt++) {
	 struct timespec end_time;

	 /* send packet  */
	 send_len = send(s, send_buf.p, read_len+4, 0);
	 if (send_len < read_len+4)
	       continue;

	 pkt_sended=1;

	 /* wait for ack  */
	 clock_gettime(CLOCK_MONOTONIC, &end_time);
	 end_time.tv_sec += TFTP_TIMEOUT / 1000;
	 end_time.tv_nsec += 1000000 * (TFTP_TIMEOUT % 1000);

	 for (;;) {
	    struct timespec cur_time;
	    struct timeval tmout;
	    fd_set fds;
	    int nfds;

	    clock_gettime(CLOCK_MONOTONIC, &cur_time);
	    if (cur_time.tv_sec - last_report_time.tv_sec >= 1) {
	       fprintf(stdout, "Uploaded %.2fKB\n", num*0.5);
	       last_report_time.tv_sec=cur_time.tv_sec;
	    }

	    if ((cur_time.tv_sec > end_time.tv_sec)
		  || ((cur_time.tv_sec == end_time.tv_sec)
		     && (cur_time.tv_nsec >= end_time.tv_nsec))) {
	       /* timeout. resend packet  */
	       break;
	    }

	    FD_ZERO(&fds);
	    FD_SET(s, &fds);

	    tmout.tv_sec = end_time.tv_sec - cur_time.tv_sec;
	    tmout.tv_usec = tmout.tv_sec == 0 ? (end_time.tv_nsec - cur_time.tv_nsec)/1000 : 0;

	    assert(tmout.tv_sec>=0);
	    assert(tmout.tv_usec>=0);

	    nfds = select(s+1, &fds, NULL, NULL, &tmout);
	    if (nfds > 0) {
	       assert(FD_ISSET(s, &fds));
	       recv_len = recv(s, recv_buf.p, sizeof(recv_buf.p), 0);
	       if ((recv_len >= 4)
		     && (recv_buf.ack_pkt.opcode = htons(TFTP_OPCODE_ACK))
		     && (recv_buf.ack_pkt.num == htons(num))) {
		  ack_recvd=1;
		  break;
	       }
	       /* not-ack packets are skipped */
	    }else if (nfds < 0) {
	       perror(NULL);
	       /* XXX */
	   }
	 } /* for(;;) */

	 if (ack_recvd)
	    break;
      } /* for(resend_cnt)  */

      if (!pkt_sended || !ack_recvd) {
	 if (!pkt_sended)
	    fprintf(stderr, "cannot send packet no %u: %s\n",
		  num, strerror(errno));
	 else
	    fprintf(stderr, "Timeout: no ack from swicth for packet %u\n", num);
	 goto fwupgrade_error;
      }

   } /* for (num=1; ; num++) */


   res = 0;
   fprintf(stdout, "Firmware uploaded\n");

fwupgrade_error:
   close(f);
   close(s);
   return res;
}

void usage(void)
{
 fprintf(stdout, "Usage: %s [-h] [-t timeout] [-p password] command\n"
       ,progname);
 return;
}

void version(void)
{
 fprintf(stdout,"%s %s\n",progname,revision);
}

void help(void)
{

 printf("%s - D-Link DES-2108/2110 management utility.\n%s\n",
       progname, revision);
 usage();
 printf(
   "Options:\n"
   "    -t, --timeout=TIMEOUT           timeout, ms, default: %u\n"
   "    -p, --password=password         switch password\n"
   "Commands:\n"
   "    [iface <iface>] scan            - scan interface\n"
   "    switch <ip> show                - show switch info\n"
   "    switch <ip> passwd [pass]       - Change password\n"
   "    switch <ip> fwupgrade <file>    - Upgrade firmware\n"
   "    switch <ip> config ipif dhcp    - set DHCP\n"
   "    switch <ip> config ipif <new_ip>/<mask> gw <gw> - set ip address\n"
   "    switch <ip> config nameloc <name> <location>    - set system name, location\n\n",
   DEFAULT_TIMEOUT
 );
 return;
}

int main(int argc, char *argv[])
{
   signed char c;
   int timeout;
   int res;
   struct sockaddr_in sw_addr;
   int password_required;
   int have_new_passwd;
   struct in_addr new_ip, new_netmask, new_gw;
   const char *wrong_argument, *param;
   enum {
      CMD_SCAN=0,
      CMD_SHOW,
      CMD_PASSWD,
      CMD_FWUPGRADE,
      CMD_CONFIG_IPIF_DHCP,
      CMD_CONFIG_IPIF_STATICIP,
      CMD_CONFIG_NAMELOC
   } cmd;
   char ifname[64];
   char password[21];
   char new_password[21];
   char system_name[20];
   char system_location[20];
   char *firmware_file;

   static struct option longopts[] = {
      {"timeout", required_argument, 0, 't'},
      {"version", no_argument, 0, 'V'},
      {"help", no_argument, 0, 'h'},
      {"password", required_argument, 0, 'p'},
      {"discovery", no_argument, 0, 0},
      {0, 0, 0, 0}
   };

   timeout=-1;
   ifname[0]='\0';
   password[0]='\0';
   new_password[0]='\0';
   password_required=0;
   have_new_passwd=0;
   cmd = CMD_SCAN;

   while ((c = getopt_long(argc, argv, "t:dp:vh?",longopts,NULL)) != -1) {
      switch (c) {
	 case 'I':
	    strncpy(ifname,optarg,sizeof(ifname)-1);
	    break;
	 case 'p':
	    strncpy(password,optarg,sizeof(password)-1);
	    break;
	 case 't':
	    timeout = strtoul(optarg,(char **)NULL, 10);
	    break;
	 case 'V':
	    version();
	    exit(0);
	    break;
	 default:
	    help();
	    exit(0);
	    break;
      }
   }
   argc -= optind;
   argv += optind;

   if (!argc) {
      help();
      exit(0);
   }

   /* Parse command  */
   wrong_argument = NULL;
   param = argv[0];

   /* scan */
   if (strncasecmp(param, "scan", sizeof("scan"))==0) {
      cmd = CMD_SCAN;
      ifname[0]='\0';
   /* interface <iface> scan  */
   }else if ((strncasecmp(param, "interface", sizeof("interface"))==0)
	 || (strncasecmp(param, "iface", sizeof("iface"))==0)
	 )
   {
      cmd = CMD_SCAN;
      if (argc < 2) {
	 fprintf(stderr, "Interface not defined\n");
	 exit(-1);
      }else {
	 strncpy(ifname, argv[1], sizeof(ifname)-1);
	 ifname[sizeof(ifname)-1]='\0';
      }
   /* switch  */
   }else if (strncasecmp(param, "switch", sizeof("switch"))==0) {
      const char *sw_name;
      struct addrinfo hints, *res0;
      int error;

      if (argc == 1) {
	 fprintf(stderr, "Switch not defined\n");
	 exit(-1);
      }

      sw_name = argv[1];
      bzero(&hints, sizeof(hints));
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
      error = getaddrinfo(sw_name, DST_BROADCAST_SERVNAME, &hints, &res0);
      if (error || res0 == NULL) {
	 fprintf(stderr, "wrong switch address `%s`: `%s`\n",
	       sw_name, error ? gai_strerror(error) : ""
	       );
	 exit(-1);
      }

      assert(res0);
      assert(res0->ai_addr);

      memcpy(&sw_addr, res0->ai_addr, sizeof(sw_addr));
      freeaddrinfo(res0);

      /* switch <ip>  */
      if (argc == 2) {
	 cmd = CMD_SHOW;
      }else {
	 const char *param = argv[2];
	 /* switch <ip> show  */
	 if (strncasecmp(param, "show", sizeof("show"))==0) {
	    cmd = CMD_SHOW;
	 /*  switch <ip> config */
	 }else if (strncasecmp(param, "config", sizeof("config"))==0) {
	    const char *param;
	    if (argc == 3) {
	       fprintf(stderr, "config parameter not defined\n");
	       exit(-1);
	    }
	    param = argv[3];
	    /* switch <ip> config ipif  */
	    if (strncasecmp(param, "ipif", sizeof("param"))==0) {
	       const char *param;
	       if (argc == 4) {
		  fprintf(stderr, "config ipif parameter not defined\n");
		  exit(-1);
	       }
	       param = argv[4];
	       /* switch <ip> config ipif dhcp*/
	       if (strncasecmp(param, "dhcp", sizeof("dhcp"))==0) {
		  cmd = CMD_CONFIG_IPIF_DHCP;
		  password_required=1;
	       /* switch <ip> config ipif <new_ip>/<mask> gw <gw> */
	       }else {
		  char str[30];
		  char *p, *ip_p, *mask_p;

		  if (argc < 7) {
		     fprintf(stderr, "ipif <new_ip>/<mask> gw <gw>\n");
		     exit(-1);
		  }
		  if (argc > 7) {
		     fprintf(stderr, "Too many arguments. ipif <new_ip>/<mask> gw <gw>\n");
		     exit(-1);
		  }

		  strncpy(str, argv[4], sizeof(str)-1);
		  str[sizeof(str)-1]='\0';
		  p = index(str, '/');
		  if (!p) {
		     fprintf(stderr, "Wrong ip/netmask `%s`\n", str);
		     exit(-1);
		  }

		  ip_p=&str[0];
		  mask_p = p+1;
		  *p='\0';

		  /* XXX: sanity check ip, mask, gw */
		  if (inet_pton(AF_INET, ip_p, &new_ip) <= 0) {
		     fprintf(stderr, "Wrong ip `%s`.\n", ip_p);
		     exit(-1);
		  }

		  if (inet_pton(AF_INET, mask_p, &new_netmask) <= 0) {
		     fprintf(stderr, "Wrong netmask `%s`.\n", mask_p);
		     exit(-1);
		  }

		  /* gw */
		  if (strncasecmp(argv[5], "gw", sizeof("gw")) != 0) {
		     fprintf(stderr, "should be gw (`%s`).\n", argv[5]);
		     exit(-1);
		  }

		  if (inet_pton(AF_INET, argv[6], &new_gw) <= 0) {
		     fprintf(stderr, "Wrong gateway `%s`.\n", argv[6]);
		     exit(-1);
		  }

		  cmd = CMD_CONFIG_IPIF_STATICIP;
		  password_required=1;
	       }
	    /* switch <ip> config nameloc  */
	    } else if (strncasecmp(param, "nameloc", sizeof("nameloc"))==0) {
	       if (argc < 6) {
		  fprintf(stderr, "name or location not defined\n");
		  exit(-1);
	       }else  if (argc == 6) {
		  cmd = CMD_CONFIG_NAMELOC;
		  password_required=1;
		  strncpy(system_name, argv[4], sizeof(system_name)-1);
		  system_name[sizeof(system_name)-1]='\0';
		  strncpy(system_location, argv[5], sizeof(system_location)-1);
		  system_location[sizeof(system_location)-1]='\0';
	       }else {
		  wrong_argument=argv[6];
	       }
	    }else
	       wrong_argument = param;
	 /*  switch <ip> passwd */
	 }else if (strncasecmp(param, "passwd", sizeof("passwd"))==0) {
	    cmd = CMD_PASSWD;
	    password_required=1;
	    if (argc == 4) {
	       char *p;
	       strncpy(new_password, argv[3], sizeof(new_password)-1);
	       new_password[sizeof(new_password)-1]='\0';
	       for (p=new_password; *p; p++) {
		  if (*p == '\n' || *p=='\r') {
		     *p = '\0';
		     break;
		  }
	       }
	       have_new_passwd=1;
	    }else if (argc > 4) {
	       wrong_argument = argv[4];
	    }
	 /*  switch <ip> fwupgrade <file> */
	 }else if (strncasecmp(param, "fwupgrade", sizeof("fwupgrade"))==0) {
	    cmd = CMD_FWUPGRADE;
	    password_required=1;
	    if (argc < 4) {
		  fprintf(stderr, "firmware not defined\n");
		  exit(-1);
	    }else if (argc > 4) {
	       wrong_argument = argv[3];
	    }else {
	       firmware_file = argv[3];
	    }
	 }else
	    wrong_argument = param;
      }
   }else
      wrong_argument = param;

   if (wrong_argument) {
      fprintf(stderr, "Wrong argument: %s\n", wrong_argument);
      exit(-1);
   }

   if (password_required && (password[0]=='\0')) {
      char *p = getpass("Password: ");
      strncpy(password, p,  sizeof(password)-1);
      password[sizeof(password)-1]='\0';
   }

   res = 0;
   switch (cmd) {
      case CMD_SCAN:
	 res = discovery(ifname,
	       timeout < 0 ? DEFAULT_SCAN_TIMEOUT : timeout);
	 break;
      case CMD_SHOW:
	 res = show(&sw_addr,
	       timeout < 0 ? DEFAULT_TIMEOUT : timeout);
	 break;
      case CMD_CONFIG_IPIF_DHCP:
	 res = config_ipif_dhcp(&sw_addr,
	       timeout < 0 ? DEFAULT_TIMEOUT : timeout,
	       password);
	 break;
      case CMD_CONFIG_IPIF_STATICIP:
	 res = config_ipif_staticip(&sw_addr,
	       timeout < 0 ? DEFAULT_TIMEOUT : timeout,
	       password, new_ip, new_netmask, new_gw);
	 break;
      case CMD_PASSWD:
	 if (!have_new_passwd) {
	    char *p = getpass("New password: ");
	    strncpy(new_password, p,  sizeof(new_password)-1);
	    new_password[sizeof(new_password)-1]='\0';
	 }
	 res = passwd(&sw_addr,
	       timeout < 0 ? DEFAULT_TIMEOUT : timeout,
	       password, new_password);
	 break;
      case CMD_CONFIG_NAMELOC:
	 res = config_nameloc(&sw_addr,
	       timeout < 0 ? DEFAULT_TIMEOUT : timeout,
	       password, system_name, system_location);
	 break;
      case CMD_FWUPGRADE:
	 res = fwupgrade(&sw_addr,
	       timeout < 0 ? DEFAULT_TIMEOUT : timeout,
	       password, firmware_file);
	 break;
      default:
	 /* UNREACHABLE  */
	 assert(0);
	 break;
   }

   return res;
}
