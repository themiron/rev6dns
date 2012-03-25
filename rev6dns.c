/*
 * rev6dns.c
 * Part of the rev6dns package
 *
 * Copyright 2010 Vladislav Grishenko <themiron@mail.ru>
 * Some ideas was taken from drpoxy package by Matthew Pratt
 * and from v6rev-dnslab.pl script
 *
 * This software is licensed under the terms of the GNU General
 * Public License (GPL). Please see the file COPYING for details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>

#include "rev6dns.h"

#define ptrsize 5
#define ptrmask ((1 << ptrsize)-1)
static char hash[] = "0123456789abcdefghijklmnopqrstuvwxyz";
#define zeromark 'z'
#define parse_addr2ptr parse_addr2ptr_32z
#define parse_ptr2addr parse_ptr2addr_32z

static struct list binds;
static char *bind_port	= BIND_PORT;
static int   bind_family= AF_UNSPEC;

static char           *netstr  = NULL;
static struct in6_addr net     = IN6ADDR_ANY_INIT;
static struct in6_addr netmask = IN6ADDR_ANY_INIT;
static unsigned int    netsize;
static char 	       netrev[NI_MAXHOST+1];

static char *domain;
static char *nserver;
static int detach = 1;

static int is_open = 0;

static void mylog(int level, char *fmt, ...)
{
	va_list ap;

	if (!is_open) {
		openlog(PACKAGE, 0, LOG_DAEMON);
		is_open = 1;
	}

	va_start(ap, fmt);
	vsyslog(level, fmt, ap);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

static void list_init(struct list *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
}

static void list_free(struct list *list)
{
	struct item *item, *next;

	for (item = list->head; item; item = next) {
		next = item->next;
		if (item->data)
			free(item->data);
		free(item);
	}
	list_init(list);
}

static struct item *list_add(struct list *list, void *data, int size)
{
	struct item *item;

	item = malloc(sizeof(struct item));
	item->next = NULL;
	item->data = NULL;
	item->size = size;

	if (data != NULL) {
		if (size == 0)
			item->size = strlen(data)+1;
		item->data = malloc(item->size);
		memcpy(item->data, data, item->size);
	}

	if (list->head == NULL)
		list->head = item;
	if (list->tail != NULL)
		list->tail->next = item;
	list->tail = item;
	list->size++;

	return item;
}

static int parse_net2addr(char *str, struct in6_addr *net, struct in6_addr *mask)
{
	char buff[INET6_ADDRSTRLEN+1];
	int i, size;

	if ((sscanf(str, "%[^/]/%u", buff, &size) != 2) ||
	    (inet_pton(AF_INET6, buff, net) != 1) ||
	    (size > 128) || (size & 0x3))
		return -1;
	for (i = (128 - size); i < 128; i++)
		mask->s6_addr32[3-i/32] |= htonl(1 << (i % 32));
	for (i = 0; i < 4; i++)
		net->s6_addr32[i] &= mask->s6_addr32[i];
	return size;
}

static void parse_addr2rev(struct in6_addr *addr, int netsize, char *str)
{
	char buff[NI_MAXHOST+1];
	int i;

	for (i = 0; i < 8; i++)
		sprintf(&buff[i*8], "%x.%x.%x.%x.",
			(ntohs(addr->s6_addr16[7-i])) & 0xf,
			(ntohs(addr->s6_addr16[7-i]) >> 4) & 0xf,
			(ntohs(addr->s6_addr16[7-i]) >> 8) & 0xf,
			(ntohs(addr->s6_addr16[7-i]) >> 12) & 0xf);
	strcpy(str, &buff[64-netsize/2]);
	strcat(str, "ip6.arpa");
}

static void parse_addr2ptr_32z(struct in6_addr *addr, int netsize, char *str)
{
	char buff[NI_MAXHOST+1];
	unsigned int num[4];
	int len = 0;
	int zero = 0;
	int cur;

	num[3] = ntohl(addr->s6_addr32[0]);
	num[2] = ntohl(addr->s6_addr32[1]);
	num[1] = ntohl(addr->s6_addr32[2]);
	num[0] = ntohl(addr->s6_addr32[3]);

	while (1) {
		cur = (num[0] & ptrmask);
		num[0] = (num[0] >> ptrsize) | (num[1] << (32-ptrsize));
		num[1] = (num[1] >> ptrsize) | (num[2] << (32-ptrsize));
		num[2] = (num[2] >> ptrsize) | (num[3] << (32-ptrsize));
		num[3] = (num[3] >> ptrsize);
		if (cur == 0) {
			zero++;
			continue;
		}
		if (zero > 0) {
			if (zero > 1) {
				buff[len++]  = zeromark;
				buff[len++]  = hash[zero];
			} else
				buff[len++]  = '0';
			zero = 0;
		}
		buff[len++] = hash[cur];
		if (!num[3] && !num[2] && !num[1] && !num[0])
			break;
	}

	buff[len] = 0;
	sprintf(str, "%s.%s", buff, domain);
}

#if 0
static void parse_addr2ptr_16(struct in6_addr *addr, int netsize, char *str)
{
	char buff[NI_MAXHOST+1];

	sprintf(buff, "%08x%08x%08x%08x.%s",
		ntohl(addr->s6_addr32[0]),
		ntohl(addr->s6_addr32[1]),
		ntohl(addr->s6_addr32[2]),
		ntohl(addr->s6_addr32[3]),
		domain);
	strncpy(str, buff, netsize/4);
	str[netsize/4] = 0;
	strcat(str, &buff[32]);
}
#endif

static int parse_ptr2addr_32z(char *str, int len, struct in6_addr *addr)
{
	unsigned int num[5] = {0,0,0,0,0};
	unsigned int cur;
	char *sym = str;
	char *hashsym;
	int zero = 0;
	int size = 0;

	while ((sym < str+len) && (size < 128)) {
		cur = *(sym++);
		if (cur == zeromark) {
			if (zero)
				return 0;
			zero = 1;
			continue;
		} else
		if (cur == 0) {
			break;
		}
		hashsym = strchr(hash, cur);
		if (hashsym == NULL)
			return 0;
		cur = hashsym - hash;
		if (zero == 0) {
			if (size%32+ptrsize >= 32)
			    num[size/32+1] |= cur >> (32-size%32);
			num[size/32] |= cur << (size%32);
			size += ptrsize;
		} else {
			size += ptrsize*cur;
			zero = 0;
		}
	}

	addr->s6_addr32[0] = htonl(num[3]);
	addr->s6_addr32[1] = htonl(num[2]);
	addr->s6_addr32[2] = htonl(num[1]);
	addr->s6_addr32[3] = htonl(num[0]);
	return 1;
}

static int parse_ptr2addr_16(char *str, int len, struct in6_addr *addr)
{
	char buff[NI_MAXHOST+1];
	int i, u16;

	for (i = 0; i < len/4; i++) {
		sprintf(buff, "%c%c%c%c",
			str[i*4+0], str[i*4+1],
			str[i*4+2], str[i*4+3]);
		errno = 0;
		u16 = strtoul(buff, NULL, 16);
		addr->s6_addr16[i] = htons(u16);
		if ((u16 == 0) && errno)
			return 0;
	}
	return 1;
}

static int parse_rev2addr(char *str, int len, struct in6_addr *addr)
{
	char buff[NI_MAXHOST+1];
	int i, size, c = 0;

	for (i = len-1; i >= 0; i--) {
		if (str[i] == '.')
			continue;
		buff[c++] = str[i];
	}
	size = c * 4;

	while (c < 32) buff[c++] = '0';
	buff[c] = 0;
                               
	if (parse_ptr2addr_16(buff, 32, addr))
		return size;
	return 0;
}

static int get_interface_addrs(int family, char *name, struct list *addrs)
{
	struct ifaddrs *ifaddrs = NULL;
	struct ifaddrs *ifa;
	int ifafamily, ret = 1;
	char buff[NI_MAXHOST+1];
	int count = 0;

	if (getifaddrs(&ifaddrs) == -1) {
		mylog(LOG_ERR, "Can't get %s interface address: %s", name, strerror(errno));
		return 0;
	}

	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		ifafamily = ifa->ifa_addr->sa_family;
		if ((ifafamily != AF_INET && ifafamily != AF_INET6) ||
		    (family != AF_UNSPEC && ifafamily != family) ||
		    (strcmp(ifa->ifa_name, name) != 0))
			continue;
		if (getnameinfo(ifa->ifa_addr,
			(ifafamily == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
			buff, sizeof(buff), NULL, 0, NI_NUMERICHOST)) {
			mylog(LOG_ERR, "Can't get %s interface address: %s", name, strerror(errno));
			ret = -1;
			break;
		}
		list_add(addrs, buff, 0);
		count++;
	}

	freeifaddrs(ifaddrs);
	if (ret > 0 && count == 0) {
		mylog(LOG_ERR, "Can't find %s interface", name);
		ret = 0;
	}
	return ret;
}

static void sig_child(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
	signal(SIGCHLD, sig_child);
}

static int socket_set_nonblock(int sock)
{
	int flags;

	if ((flags = fcntl(sock, F_GETFL, 0)) < 0)
		return -1;
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	return 1;
}

static int create_udp_socket(int family, char *hostname, char *port)
{
	int sock = -1;
	int multi_client = 1;
	int err;
	struct addrinfo *res, *cur;
	struct addrinfo hint = {
		.ai_flags = AI_PASSIVE,
		.ai_family = family,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_addrlen = 0,
		.ai_addr = 0,
		.ai_canonname = 0,
		.ai_next = 0
	};

	err = getaddrinfo(hostname, port, &hint, &res);
	if (err) {
		mylog(LOG_ERR, "getaddrinfo(): %s", gai_strerror(err));
		return -1;
	}

	for (cur = res ; cur; cur = cur->ai_next) {
		if ((sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol)) < 0) {
			mylog(LOG_WARNING, "Can't create socket: %s", strerror(errno));
			continue;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
					(char *)&multi_client,
					sizeof(multi_client)) < 0) {
			mylog(LOG_WARNING, "Can't set sock options: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}

		if (socket_set_nonblock(sock) < 0) {
			mylog(LOG_ERR, "Can't set sock to non blocking: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}

		if (bind(sock, cur->ai_addr, cur->ai_addrlen) < 0) {
			mylog(LOG_WARNING, "Can't bind socket: %s", strerror(errno));
			close(sock);
			sock = -1;
			continue;
		}

		//memcpy(server, cur->ai_addr, cur->ai_addrlen);
		//server->len = cur->ai_addrlen;

		freeaddrinfo(res);
		return sock;
	}

	freeaddrinfo(res);
	mylog(LOG_ERR, "Can't bind any socket");
	return -1;
}

static int packet_read(int sock, struct udp_packet *packet)
{
	int nread;

	memset(packet->buf, 0, sizeof(packet->buf));
	packet->src.len = sizeof(packet->src);
	if ((nread = recvfrom(sock, &packet->header, sizeof(packet->buf), 0,
			&packet->src.sa, &packet->src.len)) < 0) {
		return -1;
	}
	packet->len = nread;
	packet->request = NULL;
	return nread;
}

static int packet_write(int sock, struct udp_packet *packet)
{
	return sendto(sock, &packet->header, packet->len, 0, 
			&packet->src.sa, packet->src.len);
}

static void packet_append(struct udp_packet *packet, void *data, int len)
{
	memcpy((void*)&packet->header + packet->len, data, len);
	packet->len += len;
}

static int is_dns_query(struct udp_packet *packet)
{
	return !(ntohs(packet->header.flags) & 0x8000);
}

static int get_dns_opcode(struct udp_packet *packet)
{
	return (ntohs(packet->header.flags) & 0x7900 >> 11);
}

static struct ns_request *get_dns_request(struct udp_packet *packet)
{
	if (packet->request == NULL)
		packet->request = (struct ns_request *)&packet->buf[strlen(packet->buf)+2];
	return packet->request;
}

static int get_dns_type(struct udp_packet *packet)
{
	struct ns_request *request = get_dns_request(packet);
	return request->ns_type;
}

static int get_dns_class(struct udp_packet *packet)
{
	struct ns_request *request = get_dns_request(packet);
	return request->ns_class;
}

static int dns_set_flags(struct udp_packet *packet, int rcode)
{
	/* Keep opcode and rd flags set all others to 0 */
	packet->header.flags &= htons(0x7900);
	/* Set QR to response and RA to recursion available */
	packet->header.flags |= htons(0x8080);
	/* Set RCODE to refused */
	packet->header.flags |= htons(rcode & 0x000f);
	return 0;
}

static void decode_domain_name(char query[BUF_SIZE])
{
	char temp[BUF_SIZE];
	int i, k, len, j;

	i = 0; k = 0;
	while (query[i]) {
		len = query[i];
		i++;
		for (j = 0; j < len; j++) temp[k++] = query[i++];
		temp[k++] = '.';
	}
	temp[k-1] = 0;
	strcpy(query, temp);
}

static int encode_domain_name(char *name, char encoded_name[BUF_SIZE])
{
	int i,j,k,n;

	k = 0; i = 0;
	while (name[i]) {
		for (j = 0; name[i+j] && name[i+j] != '.'; j++);
		encoded_name[k++] = j;
		for (n = 0; n < j; n++) encoded_name[k++] = name[i+n];
		i += j + 1;
		if (!name[i-1]) break;
	}
	encoded_name[k++] = 0;
	return k;
}

static void dns_send_reply(int sock, struct udp_packet *packet, int rcode)
{
	dns_set_flags(packet, rcode);
	packet->header.total_answers = htons(packet->header.total_answers);
	packet->header.total_authority = htons(packet->header.total_authority);
	packet->header.total_additional = htons(packet->header.total_additional);
	packet_write(sock, packet);
}

static int dns_inc_total(struct udp_packet *packet, int rr)
{
	int total = 0;

	switch (rr) {
	case NS_ANSWER_RR:
		total = ++packet->header.total_answers;
		break;
	case NS_AUTHOR_RR:
		total = ++packet->header.total_authority;
		break;
	case NS_ADDTNL_RR:
		total = ++packet->header.total_additional;
		break;
	}
	return total;
}

static int dns_append_ns(int sock, struct udp_packet *packet, int rr, char *zone, char *nserver)
{
	struct ns_answer dns_ans;
	char tmp1[BUF_SIZE], tmp2[BUF_SIZE];

	mylog(LOG_DEBUG, "append ns: %s @ %s", zone, nserver);

	encode_domain_name(nserver, tmp1);

	dns_ans.ns_name  = htons(0xc00c);
	dns_ans.ns_type  = htons(NS_TYPE_NS);
	dns_ans.ns_class = htons(NS_CLASS_IN);
	dns_ans.ns_ttl   = htons(60);
	dns_ans.ns_len   = htons(strlen(tmp1)+1);

	if (zone) {
		encode_domain_name(zone, tmp2);
		packet_append(packet, &tmp2, strlen(tmp2)+1);
		packet_append(packet, &dns_ans.ns_type, sizeof(dns_ans)-sizeof(dns_ans.ns_name));
	} else {
		packet_append(packet, &dns_ans, sizeof(dns_ans));
	}
	packet_append(packet, &tmp1, strlen(tmp1)+1);

	return dns_inc_total(packet, rr);
}

static int dns_append_soa(int sock, struct udp_packet *packet, int rr, char *zone, char *nserver, char *domain)
{
	struct ns_answer dns_ans;
	char tmp1[BUF_SIZE], tmp2[BUF_SIZE], tmp3[BUF_SIZE];
	int serial  = htonl(1);
	int refresh = htonl(3600);
	int retry   = htonl(900);
	int expire  = htonl(86400);
	int minimum = htonl(900);

	mylog(LOG_DEBUG, "append soa: %s @ %s", zone, nserver);

	sprintf(tmp1, "postmaster.%s", domain);
	encode_domain_name(tmp1, tmp2);
	encode_domain_name(nserver, tmp1);

	dns_ans.ns_name  = htons(0xc00c);
	dns_ans.ns_type  = htons(NS_TYPE_SOA);
	dns_ans.ns_class = htons(NS_CLASS_IN);
	dns_ans.ns_ttl   = htons(60);
	dns_ans.ns_len   = htons(strlen(tmp1)+strlen(tmp2)+2+20);

	if (zone) {
		encode_domain_name(zone, tmp3);
		packet_append(packet, &tmp3, strlen(tmp3)+1);
		packet_append(packet, &dns_ans.ns_type, sizeof(dns_ans)-sizeof(dns_ans.ns_name));
	} else {
		packet_append(packet, &dns_ans, sizeof(dns_ans));
	}

	packet_append(packet, &tmp1, strlen(tmp1)+1);
	packet_append(packet, &tmp2, strlen(tmp2)+1);
	packet_append(packet, &serial, sizeof(serial));
	packet_append(packet, &refresh, sizeof(refresh));
	packet_append(packet, &retry, sizeof(retry));
	packet_append(packet, &expire, sizeof(expire));
	packet_append(packet, &minimum, sizeof(minimum));

	return dns_inc_total(packet, rr);
}

static int dns_append_ptr(int sock, struct udp_packet *packet, int rr, char *ptr)
{
	struct ns_answer dns_ans;
	char tmp[BUF_SIZE];

	mylog(LOG_DEBUG, "append ptr: %s", ptr);

	encode_domain_name(ptr, tmp);

	dns_ans.ns_name  = htons(0xc00c);
	dns_ans.ns_type  = htons(NS_TYPE_PTR);
	dns_ans.ns_class = htons(NS_CLASS_IN);
	dns_ans.ns_ttl   = htons(60);
	dns_ans.ns_len   = htons(strlen(tmp)+1);

    	packet_append(packet, &dns_ans, sizeof(dns_ans));
	packet_append(packet, &tmp, strlen(tmp)+1);

	return dns_inc_total(packet, rr);
}

static int dns_append_aaaa(int sock, struct udp_packet *packet, int rr, struct in6_addr *addr)
{
	struct ns_answer dns_ans;
	char tmp[INET6_ADDRSTRLEN+1];

	inet_ntop(AF_INET6, addr, tmp, sizeof(tmp));
	mylog(LOG_DEBUG, "append ipv6 addr: %s", tmp);

	dns_ans.ns_name  = htons(0xc00c);
	dns_ans.ns_type  = htons(NS_TYPE_AAAA);
	dns_ans.ns_class = htons(NS_CLASS_IN);
	dns_ans.ns_ttl   = htonl(60);
	dns_ans.ns_len   = htons(sizeof(struct in6_addr));

    	packet_append(packet, &dns_ans, sizeof(dns_ans));
	packet_append(packet, addr, sizeof(struct in6_addr));

	return dns_inc_total(packet, rr);
}

static int parse_packet(int sock, struct udp_packet *packet)
{
	char query[BUF_SIZE], tmp[BUF_SIZE], *found;
	char *zone = NULL;
	int opcode, type, class;
	int rcode = NS_RCODE_OK;
	int ret = 0;
	struct in6_addr addr;
	unsigned int index;

	if (!is_dns_query(packet)) {
		dns_send_reply(sock, packet, NS_RCODE_REFUSE);
		return 0;
	}

	opcode = get_dns_opcode(packet);
	type = get_dns_type(packet);
	class = get_dns_class(packet);

	strcpy(query, packet->buf);
	decode_domain_name(query);

	if (class != NS_CLASS_IN && class != NS_CLASS_ANY) {
		mylog(LOG_DEBUG, "Unsupported query %d/%d/%d: %s", opcode, type, class, query);
		dns_send_reply(sock, packet, NS_RCODE_NOTIMP);
		return 0;
	}

	switch (opcode) {
	case 0:
		mylog(LOG_DEBUG, "Standart query %d/%d/%d: %s", opcode, type, class, query);
		break;
	case 1:
		mylog(LOG_DEBUG, "Inverse query %d/%d/%d: %s", opcode, type, class, query);
		dns_send_reply(sock, packet, NS_RCODE_NOTIMP);
		break;
	default:
		mylog(LOG_DEBUG, "Unsupported query: %d/%d/%d: %s", opcode, type, class, query);
		dns_send_reply(sock, packet, NS_RCODE_NOTIMP);
		return 0;
	}

	if ((found = strstr(query, netrev)) != NULL) {
		zone = netrev;
		index = (found - query);
		if (index == 0) {
			if (type == NS_TYPE_ANY)
				ret += dns_append_soa(sock, packet, NS_ANSWER_RR, NULL, nserver, domain);
			if (type == NS_TYPE_NS || type == NS_TYPE_ANY)
				ret += dns_append_ns(sock, packet, NS_ANSWER_RR, NULL, nserver);
		} else
		if ((index <= 64) &&
		    (index = parse_rev2addr(query, index + netsize/2, &addr))) {
			if (type == NS_TYPE_PTR || type == NS_TYPE_ANY) {
				parse_addr2ptr(&addr, index, tmp);
				ret += dns_append_ptr(sock, packet, NS_ANSWER_RR, tmp);
				ret += dns_append_ns(sock, packet, NS_AUTHOR_RR, zone, nserver);
			}
		} else
			rcode = NS_RCODE_DOMERR;
	} else
	if ((found = strstr(query, domain)) != NULL) {
		zone = domain;
		index = (found - query);
		if (index == 0) {
			if (type == NS_TYPE_ANY)
				ret += dns_append_soa(sock, packet, NS_ANSWER_RR, NULL, nserver, domain);
			if (type == NS_TYPE_NS || type == NS_TYPE_ANY)
				ret += dns_append_ns(sock, packet, NS_ANSWER_RR, NULL, nserver);
		} else
		if ((index > 4) &&
		    (parse_ptr2addr(query, index-1, &addr))) {
			if (type == NS_TYPE_AAAA || type == NS_TYPE_ANY) {
				ret += dns_append_aaaa(sock, packet, NS_ANSWER_RR, &addr);
				ret += dns_append_ns(sock, packet, NS_AUTHOR_RR, zone, nserver);
			} else
			if (type == NS_TYPE_NS) {
				ret += dns_append_ns(sock, packet, NS_ANSWER_RR, NULL, nserver);
			}
		} else
			rcode = NS_RCODE_DOMERR;
	} else
		rcode = NS_RCODE_REFUSE;

	if ((ret == 0) && (rcode != NS_RCODE_REFUSE))
		ret += dns_append_soa(sock, packet, NS_AUTHOR_RR, zone, nserver, domain);

	dns_send_reply(sock, packet, rcode);

	return rcode;
}

static void usage(void)
{
	mylog(LOG_ERR, "usage: %s [-d] [-i interface] [-a adress] [-p port] [-4 | -6] nameserver domain subnet", PACKAGE);
}

int main(int argc, char *argv[])
{
	fd_set set;
	int maxfd = -1;
	struct timeval tv;
	pid_t pid;
	int ret, opt, sock, n;
	struct udp_packet packet;
	struct list ifs, addrs;
	struct item *item;

	list_init(&binds);
	list_init(&ifs);
	list_init(&addrs);

	while((opt = getopt(argc, argv, "i:a:p:46d")) != -1) {
		switch (opt) {
		case '4':
			bind_family = AF_INET;
			break;
		case '6':
			bind_family = AF_INET6;
			break;
		case 'i':
			list_add(&ifs, optarg, 0);
			break;
		case 'a':
			list_add(&addrs, optarg, 0);
			break;
		case 'p':
			bind_port = optarg;
			break;
		case 'd':
			detach = 0;
			break;
		default:
			usage();
			return 1;
		}
	}

	if (argc < optind+2) {
		usage();
		return 1;
	}

	nserver = argv[optind];
	domain = argv[optind+1];
	netstr = argv[optind+2];

	if ((netsize = parse_net2addr(netstr, &net, &netmask)) <= 0) {
		mylog(LOG_ERR, "Can't parse ipv6 net address: %s", netstr);
		return 1;
	}

	parse_addr2rev(&net, netsize, netrev);

	for (item = ifs.head; item; item = item->next) {
		if (get_interface_addrs(bind_family, item->data, &addrs) == 0) {
			list_free(&ifs);
			return 1;
		}
	}
	list_free(&ifs);

	if (addrs.size == 0) {
		list_add(&addrs, NULL, 0);
	}

	for (item = addrs.head; item; item = item->next) {
		if ((sock = create_udp_socket(bind_family, item->data, bind_port)) < 0) {
			list_free(&addrs);
			return 1;
		}
		list_add(&binds, NULL, sock);
	}
	list_free(&addrs);

	if (detach) {
		switch (fork()) {
		case -1:
			mylog(LOG_ERR, "Unable to fork");
			_exit(1);
		case 0:
			close(0);
			close(1);
			close(2);
			break;
		default:
			_exit(0);
		}
	}

	mylog(LOG_INFO, "Reverse IPv6 DNS ver.%s started", VERSION);
	mylog(LOG_INFO, "Map %s to *.%s using %s", netstr, domain, nserver);

        signal(SIGCHLD, sig_child);
	while (1) {
		FD_ZERO(&set);
		maxfd = -1;
		for (item = binds.head; item; item = item->next) {
			sock = item->size;
			FD_SET(sock, &set);
			if (sock > maxfd) maxfd = sock;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		ret = select(maxfd+1, &set, NULL, NULL, &tv);
		if (ret == 0)
			continue;
		pid = -1;
		for (item = binds.head; item; item = item->next) {
			sock = item->size;
			if (!FD_ISSET(sock, &set))
				continue;
			n = packet_read(sock, &packet);
			if (n < 0)
				/* no data */
				continue;
			if (n < sizeof(struct ns_header)+1)
				/* packet with invalid size */
				continue;
			if ((pid = fork()) == 0)
				break;
		}
		if (pid == 0)
			break;
	}


	signal(SIGCHLD, SIG_IGN);

	parse_packet(sock, &packet);
        close(sock);

	return 0;
}
