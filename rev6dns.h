/*
 * rev6dns.h
 * Part of the rev6dns package
 *
 * Copyright 2010 Vladislav Grishenko <themiron@mail.ru>
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

#define DEFAULT_TTL	60

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
	uint16_t id;
	uint16_t flags;
	uint16_t total_questions;
	uint16_t total_answers;
	uint16_t total_authority;
	uint16_t total_additional;
} __attribute__((packed));

struct ns_request {
	uint16_t ns_type;
	uint16_t ns_class;
} __attribute__((packed));

struct ns_answer {
	uint16_t ns_name;
	uint16_t ns_type;
	uint16_t ns_class;
	uint32_t ns_ttl;
	uint16_t ns_len;
} __attribute__((packed));

struct ns_ptr {
	char *name, *ptr;
	struct ns_ptr *next;
} __attribute__((packed));

struct ns_cname {
	char *alias, *target;
	struct ns_cname *next;
} __attribute__((packed));

struct ns_soa {
	char *mname, *rname;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
} __attribute__((packed));

struct udp_packet {
	struct ns_header header;
	char buf[BUF_SIZE];
	int len;
	struct ns_request *request;
	struct all_sockaddr src;
};
