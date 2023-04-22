#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ipset_test_rpc.h"
#include "ipset_test.h"

// #define DEBUG

static CLIENT *clnt;
static char *server = "localhost";

int init_ipset_test_clnt() {
    clnt = clnt_create(server, 
		IPSET_TEST_PROG,
		IPSET_TEST_VERS,
		"udp"
	);

	if (clnt == (CLIENT *)NULL) {
		clnt_pcreateerror(server);
		return EXIT_FAILURE;
	}
    return EXIT_SUCCESS;
}

int test_ipaddr_in_ipset(char *setname, int af, void* ipaddr) {
    int *ret;
    struct test_ipaddr_in_ipset_req req = {
		.setname = {'\0'},
		.af = af,
	};
	memcpy(req.setname, setname, strlen(setname) + 1);
    if (af == AF_INET) {
        memcpy(&(req.ip4addr.addr), &(((struct sockaddr_in *) ipaddr)->sin_addr.s_addr), sizeof(ip4_addr) / sizeof(char));
    }
    if (af == AF_INET6) {
        memcpy(&(req.ip6addr.addr), ((struct sockaddr_in6 *) ipaddr)->sin6_addr.s6_addr, sizeof(ip6_addr) / sizeof(char));
    }

#ifdef DEBUG
    fprintf(stderr, "%ld: setname = %s, af = %d, ", time(NULL), req.setname, req.af);
    if (req.af == AF_INET) {
        fprintf(stderr, "ipaddr = ");
        for (int i = 0; i < 4; ++i) {
            fprintf(stderr, "%02x", ((char *)&(req.ip4addr.addr))[i]);
        }
        fprintf(stderr, "\n");
    } else if (req.af == AF_INET6) {
        fprintf(stderr, "ipaddr = ");
        for (int i = 0; i < 16; ++i) {
            fprintf(stderr, "%02x", req.ip6addr.addr[i]);
        }
        fprintf(stderr, "\n");
    }
#endif

    ret = test_ipaddr_in_ipset_1(&req, clnt);

	if (ret == (int *)NULL) {
		clnt_perror(clnt, server);
		return EXIT_FAILURE;
	}
    return *ret;
}

int deinit_ipet_test_clnt() {
    if (clnt != (CLIENT *)NULL) {
        clnt_destroy(clnt);
        clnt = NULL;
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}