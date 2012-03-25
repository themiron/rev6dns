/*
 * rev6dns.h
 * Part of the rev6dns package
 *
 * Copyright 2010 Vladislav Grishenko <themiron@mail.ru.com>
 * Some ideas was taken from drpoxy package by Matthew Pratt.
 * and from v6rev-dnslab.pl script
 *
 * This software is licensed under the terms of the GNU General
 * Public License (GPL). Please see the file COPYING for details.
 *
 */

#define PACKAGE		"rev6dns"
#define VERSION		"0.3"

#define BIND_PORT	"53"

#define BUF_SIZE	2048

#define NS_TYPE_A	1
#define NS_TYPE_NS	2
#define NS_TYPE_CNAME	5
#define NS_TYPE_SOA	6
#define NS_TYPE_AAAA	28
#define NS_TYPE_PTR	12
#define NS_TYPE_ANY	255

#define NS_CLASS_IN	1
#define NS_CLASS_ANY	255

#define NS_ANSWER_RR	0
#define NS_AUTHOR_RR	1
#define NS_ADDTNL_RR	2

#define NS_RCODE_OK	0
#define NS_RCODE_FMTERR	1
#define NS_RCODE_FAIL	2
#define NS_RCODE_DOMERR	3
#define NS_RCODE_NOTIMP	4
#define NS_RCODE_REFUSE	5

struct all_addr {
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
	int len;
};

struct all_sockaddr {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
	int len;
};

struct item {
	void *data;
	int   size;
	struct item *next;
};

struct list {
	struct item *head;
	struct item *tail;
	int size;
};

struct ns_header {
	short int id;
	short int flags;
	short int total_questions;
	short int total_answers;
	short int total_authority;
	short int total_additional;
};

struct ns_request {
	short int ns_type;
	short int ns_class;
};

struct ns_answer {
	short int ns_name;
	short int ns_type;
	short int ns_class;
	short int ns_ttl;
	short int ns_ttl2;
	short int ns_len;
};

struct ns_ptr {
	char *name, *ptr;
	struct ns_ptr *next;
};

struct ns_cname {
	char *alias, *target;
	struct ns_cname *next;
};

struct ns_soa {
	char *mname, *rname;
	int serial;
	int refresh;
	int retry;
	int expire;
	int minimum;
};

struct udp_packet {
	struct ns_header header;
	char buf[BUF_SIZE];
	int len;
	struct ns_request *request;
	struct all_sockaddr src;
};
