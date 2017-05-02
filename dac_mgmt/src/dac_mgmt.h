#ifndef __DAC_MGMT_H__
#define __DAC_MGMT_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define DEBUG 1

#ifdef DEBUG
#define DAC_ERR(fmt,args...)    printf(fmt,##args)
#define DAC_INFO(fmt,args...)   printf(fmt,##args)
#define DAC_DBG(fmt,args...)    printf(fmt,##args)
#else
#define DAC_ERR(fmt,args...)    printf(fmt,##args)
#define DAC_INFO(fmt,args...)   printf(fmt,##args)
#define DAC_DBG(fmt,args...)    do{ }while(0)
#endif

#define MIN(a, b)   (((a) < (b)) ? (a) : (b))
#define MAX(a, b)   (((a) > (b)) ? (a) : (b))

#define CTL_PORT    (20200)
#define BUF_SIZE   (1024)

#define MAX_PAYLOAD     (256)
#define NETLINK_DAC 25
#define MAX_CLIENT  64
#define DHCP_LEASES_PATH "/tmp/dhcp.leases"
#define ARP_PROC_PATH	"/proc/net/arp"
#define BR_NAME "br-lan"

typedef int (*get_info) (int fd, struct ifreq ifr, void *ctx);

struct host {
    int sock_fd;
    in_addr_t ip_addr;
    unsigned char mac_addr[6];
};

struct target_dev {
    unsigned char mac_addr[6];
    in_addr_t ip_addr;
};

#endif