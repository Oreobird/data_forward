#include <time.h>
#include <signal.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>

#include "dac_mgmt.h"

int re_srv_num = 0;
struct host lo_srv;
struct host re_cli;
struct host re_srv_list[MAX_CLIENT];

static char *get_time(void)
{
    static char date_str[20];
    time_t date;

    time(&date);
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", localtime(&date));
    return date_str;
}

static int get_ip(int fd, struct ifreq ifr,  void *ctx)
{
    struct sockaddr_in *ip = (struct sockaddr_in *)ctx;

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        DAC_ERR("ioctl SIOCGIFADDR error\n");
        return -1;
    }
    memcpy(ip, &ifr.ifr_addr, sizeof(struct sockaddr_in));
    return 0;
}

static int get_netmask(int fd, struct ifreq ifr,  void *ctx)
{
    struct sockaddr_in *netmask = (struct sockaddr_in *)ctx;

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0)
    {
        DAC_ERR("ioctl SIOCGIFNETMASK error\n");
        return -1;
    }
    memcpy(netmask, &ifr.ifr_addr, sizeof(struct sockaddr_in));
    return 0;
}

static int get_iface_info(char *ifname, void *ctx, get_info get_info_func)
{
    int fd = -1;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        DAC_ERR("get_iface_addr error\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

    get_info_func(fd, ifr, ctx);

    close(fd);
    return 0;
}


static int get_remote_server_info()
{
    FILE *fp = NULL;
    char line_buf[256] = {0};
    char dummy1[32] = {0};
    char dummy2[32] = {0};
    char dummy3[32] = {0};
    char mac_str[32] = {0};
    char ip[32] = {0};
    unsigned char mac[6] = {0};

    struct sockaddr_in br_netmask;
    struct sockaddr_in br_ip;
    int br_subnet = 0;

    fp = fopen(DHCP_PATH, "r");
    if (!fp)
    {
        DAC_ERR("Open %s failed\n", DHCP_PATH);
        return -1;
    }

    get_iface_info(BR_NAME, &br_ip, get_ip);
    get_iface_info(BR_NAME, &br_netmask, get_netmask);
    br_subnet = (br_ip.sin_addr.s_addr & br_netmask.sin_addr.s_addr);

    memset(re_srv_list, 0, sizeof(re_srv_list));
    re_srv_num = 0;
    while (fgets(line_buf, sizeof(line_buf), fp) != NULL)
    {
        memset(mac_str, 0, sizeof(mac_str));
        memset(mac, 0, sizeof(mac));
        memset(ip, 0, sizeof(ip));
        sscanf(line_buf, "%s %s %s %s %s", dummy1, mac_str, ip, dummy2, dummy3);
        if ((inet_addr(ip) & br_netmask.sin_addr.s_addr) == br_subnet)
        {
            sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
            memcpy(re_srv_list[re_srv_num].mac_addr, mac, sizeof(mac));

            re_srv_list[re_srv_num].ip_addr = inet_addr(ip);
            re_srv_num++;
            if (re_srv_num >= MAX_CLIENT)
            {
                break;
            }
        }
    }

    fclose(fp);
    return 0;
}

#ifdef DEBUG
static void print_dev_list()
{
    int i = 0;
    struct in_addr addr;
    char mac[18] = {0};
    for (i = 0; i < re_srv_num; i++)
    {
        addr.s_addr = re_srv_list[i].ip_addr;
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", re_srv_list[i].mac_addr[0],
                re_srv_list[i].mac_addr[1], re_srv_list[i].mac_addr[2], re_srv_list[i].mac_addr[3],
                re_srv_list[i].mac_addr[4], re_srv_list[i].mac_addr[5]);
        printf("dev:%d--mac:%s--ip:%s\n", i, mac, inet_ntoa(addr));
    }
}
#endif

static int maxfd(void)
{
    int fd = MAX(lo_srv.sock_fd, re_cli.sock_fd);
    int i = 0;

    for (i = 0; i < re_srv_num; i++)
    {
        fd = MAX(fd, re_srv_list[i].sock_fd);
    }

    return fd + 1;
}

static void close_sockets()
{
    int i = 0;
    for (i = 0; i < re_srv_num; i++)
    {
        if (re_srv_list[i].sock_fd != -1)
        {
            close(re_srv_list[i].sock_fd);
        }
    }

    if (re_cli.sock_fd != -1)
    {
        close(re_cli.sock_fd);
    }
}

static int build_local_server(const char* addr_str, int port)
{
    int ret = -1;
    int optval = 1;
    struct sockaddr_in addr;

    lo_srv.sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (lo_srv.sock_fd < 0)
    {
        DAC_ERR("create socket failed\n");
        return -1;
    }

    ret = setsockopt(lo_srv.sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (ret < 0)
    {
        DAC_ERR("setsockopt failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (addr_str != NULL)
    {
        addr.sin_addr.s_addr = inet_addr(addr_str);
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    addr.sin_port = htons(port);
    lo_srv.ip_addr = addr.sin_addr.s_addr;

    ret = bind(lo_srv.sock_fd, (struct sockaddr*)&(addr), sizeof(addr));
    if (ret < 0)
    {
        DAC_ERR("Bind addr: %s failed\n", addr_str);
        return -1;
    }

    ret = listen(lo_srv.sock_fd, 5);
    if (ret < 0)
    {
        DAC_ERR("Listen to addr: %s failed\n", addr_str);
        return -1;
    }

    return 0;
}

static int connect_remote_server()
{
    int i = 0;
    int ret = 0;
    struct sockaddr_in addr;

    DAC_DBG("=====connect_remote_server======\n");
    for (i = 0; i < re_srv_num; i++)
    {
        int flags = 0;

        re_srv_list[i].sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (re_srv_list[i].sock_fd < 0)
        {
            DAC_ERR("Create local client socket failed\n");
            continue;
        }

        flags = fcntl(re_srv_list[i].sock_fd, F_GETFL, 0);
        fcntl(re_srv_list[i].sock_fd, F_SETFL, flags | O_NONBLOCK);

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(CTL_PORT);

        addr.sin_addr.s_addr = re_srv_list[i].ip_addr;
        DAC_INFO("--> %s Try to connect %s ...\n", get_time(), inet_ntoa(addr.sin_addr));

        ret = connect(re_srv_list[i].sock_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
        if (ret < 0)
        {
            DAC_ERR("--> %s Connect to remote server: %s failed!\n", get_time(), inet_ntoa(addr.sin_addr));
            if (re_srv_list[i].sock_fd != -1)
            {
                close(re_srv_list[i].sock_fd);
                re_srv_list[i].sock_fd = -1;
            }
            continue;
        }

        DAC_INFO("--> %s Connect to remote server: %s success\n", get_time(), inet_ntoa(addr.sin_addr));
    }
    return 0;
}

static int set_target_dev(struct target_dev tdev)
{
    struct nlmsghdr *nh;
    struct sockaddr_nl sa;
    struct iovec iov  = {nh, nh->nlmsg_len};
    struct msghdr msg;
    int nl_fd = -1;
    int ret = -1;

    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_DAC);
    if (nl_fd < 0)
    {
        DAC_ERR("netlink socket failed\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 0;
    sa.nl_pid = 0;

    ret = bind(nl_fd, (struct sockaddr *) &sa, sizeof(sa));
    if (ret < 0)
    {
        DAC_ERR("netlink bind failed\n");
        close(nl_fd);
        return -1;
    }

    nh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (nh == NULL)
    {
        DAC_ERR("nlmsghdr malloc failed\n");
        close(nl_fd);
        return -1;
    }

    memset(nh, 0, MAX_PAYLOAD);
    nh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nh->nlmsg_pid = 0;
    nh->nlmsg_flags = 0;
    nh->nlmsg_type = NLMSG_NOOP;

    memcpy(NLMSG_DATA(nh), &tdev, sizeof(nh));

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nh;
    iov.iov_len = nh->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(nl_fd, &msg, 0);

    close(nl_fd);
    free(nh);
    return 0;
}

static void set_forward_target(int reply_srv)
{
    struct target_dev tdev;

    memcpy(tdev.mac_addr, re_srv_list[reply_srv].mac_addr, sizeof(tdev.mac_addr));
    tdev.ip_addr = re_srv_list[reply_srv].ip_addr;
    set_target_dev(tdev);
}

static int room_to_door(int reply_srv, char *buffer, fd_set rfds)
{
    int i = 0;
    int data_len = recv(re_srv_list[reply_srv].sock_fd, buffer, sizeof(buffer), 0);
    if (data_len <= 0)
    {
        DAC_ERR("forward_data: recv remote server failed\n");
        if (re_srv_list[reply_srv].sock_fd != -1)
        {
            FD_CLR(re_srv_list[reply_srv].sock_fd, &rfds);
            close(re_srv_list[reply_srv].sock_fd);
            re_srv_list[reply_srv].sock_fd = -1;
        }
        return -1;
    }

    set_forward_target(reply_srv);

    DAC_DBG("--> %s recv data from ROOM, try to forward to DOOR\n", get_time());
    send(re_cli.sock_fd, buffer, data_len, 0);

    for (i = 0; i < re_srv_num; i++)
    {
        if (i != reply_srv && re_srv_list[i].sock_fd != -1)
        {
            FD_CLR(re_srv_list[i].sock_fd, &rfds);
            close(re_srv_list[i].sock_fd);
            re_srv_list[i].sock_fd = -1;
        }
    }
    return 0;
}


static int door_to_room(char *buffer)
{
    int i = 0;
    int data_len = recv(re_cli.sock_fd, buffer, sizeof(buffer), 0);
    if (data_len <= 0)
    {
        DAC_ERR("forward_data: recv remote client failed\n");
        close_sockets();
        return -1;
    }

    DAC_DBG("--> %s recv data from DOOR, try to forward to all ROOM apps\n", get_time());
    for (i = 0; i < re_srv_num; i++)
    {
        if (re_srv_list[i].sock_fd != -1)
        {
            send(re_srv_list[i].sock_fd, buffer, data_len, 0);
        }
    }
    return 0;
}

static void forward_data(void)
{
    fd_set rfds;
    char buffer[BUF_SIZE];

    int i = 0;
    DAC_DBG("=====forward_data======\n");
    while (1)
    {
        FD_ZERO(&rfds);
        if (re_cli.sock_fd != -1)
        {
            FD_SET(re_cli.sock_fd, &rfds);
        }

        for (i = 0; i < re_srv_num; i++)
        {
            if (re_srv_list[i].sock_fd != -1)
            {
                FD_SET(re_srv_list[i].sock_fd, &rfds);
            }
        }

        memset(buffer, 0, sizeof(buffer));

        if (select(maxfd(), &rfds, NULL, NULL, NULL) < 0)
        {
            DAC_ERR("forward_data: select() failed\n");
            break;
        }

        if (FD_ISSET(re_cli.sock_fd, &rfds))
        {
            if (door_to_room(buffer) < 0)
            {
                DAC_ERR("forward_data: door to room failed\n");
                break;
            }
        }

        for (i = 0; i < re_srv_num; i++)
        {
            if (re_srv_list[i].sock_fd != -1
                    && FD_ISSET(re_srv_list[i].sock_fd, &rfds))
            {
                if (room_to_door(i, buffer, rfds) == 0)
                {
                    break;
                }
            }
        }
    }
}

static int handle_call()
{
    int ret = -1;

    ret = get_remote_server_info();
    if (ret < 0)
    {
        DAC_ERR("Get remote server info failed\n");
        return -1;
    }

    ret = connect_remote_server();
    if (ret < 0)
    {
        DAC_ERR("Connect remote server failed\n");
        return -1;
    }

    forward_data();
    return 0;
}

static int wait_for_call()
{
    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);

    re_cli.sock_fd = accept(lo_srv.sock_fd, (struct sockaddr *) &addr, &addr_len);
    if (re_cli.sock_fd < 0)
    {
        DAC_ERR("Wait for call: accept() failed\n");
        return -1;
    }

    re_cli.ip_addr = addr.sin_addr.s_addr;

    DAC_INFO("--> %s Call from %s\n", get_time(), inet_ntoa(addr.sin_addr));
    //TODO: add static route in BeeBox
    //route add -net 192.168.100.0 netmask 255.255.255.0 gw 192.168.1.2 dev br-lan
    return 0;
}

int main(int argc, char **argv)
{
    int ret = -1;
    char *ip_addr = NULL;

    if (argc == 2)
    {
        ip_addr = argv[1];
        DAC_INFO("Bind ip: %s\n", ip_addr);
    }

    ret = build_local_server(ip_addr, CTL_PORT);
    if (ret < 0)
    {
        DAC_ERR("init server failed\n");
        return -1;
    }

    signal(SIGCHLD, SIG_IGN);

    while (1)
    {
        ret = wait_for_call();
        if (ret < 0)
        {
            DAC_ERR("wait for call failed\n");
            break;
        }

        handle_call();
    }

    close_sockets();

    return 0;
}
