#pragma once

#define IPADDR_IN_IPSET 0xf1
#define IPADDR_NOT_IN_IPSET 0xf2

#define IP_SET_MAXNAMELEN 32

extern int init_ipset_test_clnt();
extern int test_ipaddr_in_ipset(char *setname, int af, void* ipaddr);
extern int deinit_ipet_test_clnt();