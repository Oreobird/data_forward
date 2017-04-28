/********************************************************
*
* FILE NAME  :   dac_forward.c
* VERSION    :   1.0
* DESCRIPTION:   door access control module
*
* AUTHOR     :   zhongguanshi <zhongguanshi@evergrande.cn>
* CREATE DATE:   05/04/2017
*
*********************************************************/
#include <linux/module.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h> /*in_aton()*/
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netlink.h>


#include "dac_forward.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dac_forward Module");
MODULE_AUTHOR("Zhong Guanshi");
MODULE_ALIAS("dac_forward");

#define DAC_DBG (1)

static struct sock *nl_sk;
static struct target_dev reply_dev = {{0x00, 0x02, 0x00, 0x00, 0x8f, 0x51}, 0};
static struct target_dev beebox = {{0xD2, 0xEE, 0xFD, 0x79, 0xBB, 0x6C}, 0};
static unsigned char up_router_mac[6] = {0x00}; //记录面板路由器的MAC地址

static void print_src_ip(__be32 ip)
{
    printk("source ip address: %pI4\n", &ip);
}
static void print_dst_ip(__be32 ip)
{
    printk("destination ip address: %pI4\n", &ip);
}

static void print_src_mac(unsigned char* src_mac_addr)
{
    printk("source mac address: %pM\n", src_mac_addr);
}

static void print_dst_mac(unsigned char* dst_mac_addr)
{
    printk("destination mac address: %pM\n", dst_mac_addr);
}

static void print_pkt_info(struct sk_buff *skb)
{
#ifdef DAC_DBG
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;

    printk("=====================printk_pkt_info=====================\n");
    ethh = eth_hdr(skb);
    print_src_mac(ethh->h_source);
    print_dst_mac(ethh->h_dest);

    iph = ip_hdr(skb);
    print_src_ip(iph->saddr);
    print_dst_ip(iph->daddr);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
        printk("source port: %d\n",ntohs(tcph->source));
        printk("destination port: %d\n", ntohs(tcph->dest));
        //payload = (unsigned char*)((unsigned char*)tcph + (tcph->doff << 2));
        //printk("payload:%s\n", payload);
        //printk("===cmd:%0x%0x\n", payload[8], payload[9]);
    }
#endif
}


static unsigned char *get_dev_mac_addr(const unsigned char *dev_name)
{
    struct net_device *dev = dev_get_by_name(&init_net, dev_name);
    return dev->dev_addr;
}

static void tcp_check_sum(struct iphdr *iph)
{
    struct tcphdr *tcph;
    int tcp_len = 0;
    tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
    tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);
    tcph->check = 0;
    tcph->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr, csum_partial(tcph, tcp_len, 0));
}

static void udp_check_sum(struct iphdr *iph)
{
    struct udphdr *udph;
    int udp_len = 0;
    udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
    udp_len = ntohs(iph->tot_len) - (iph->ihl << 2);
    udph->check = 0;
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len,
                        IPPROTO_UDP, csum_partial((char *)udph, udp_len, 0));
}

static int do_check_sum(struct sk_buff *skb)
{
    struct iphdr *iph;

    iph = ip_hdr(skb);
    ip_send_check(iph);

    skb->pkt_type = PACKET_OTHERHOST;
    skb->ip_summed = CHECKSUM_NONE;
    skb->dev = dev_get_by_name(&init_net, "br-lan");
    if (skb->dev == NULL) {
        return -1;
    }

    if (iph->protocol == IPPROTO_TCP) {
        tcp_check_sum(iph);
    } else if (iph->protocol == IPPROTO_UDP) {
        udp_check_sum(iph);
    }

    return 0;
}

static int mangle_src_addr(struct sk_buff *skb, struct target_dev *tdev)
{
    struct ethhdr *ethh;
    struct iphdr *iph;

    ethh = eth_hdr(skb);
    if (ethh == NULL) {
        return -1;
    }
    memcpy(ethh->h_dest, up_router_mac, sizeof(ethh->h_dest));
    memcpy(ethh->h_source, tdev->mac_addr, sizeof(ethh->h_source));

    iph = ip_hdr(skb);
    if (iph == NULL) {
         return -1;
    }
    iph->saddr = tdev->ip_addr;

    return 0;
}

static int mangle_dst_addr(struct sk_buff *skb, struct target_dev *tdev)
{
    struct ethhdr *ethh;
    struct iphdr *iph;

    ethh = eth_hdr(skb);
    if (ethh == NULL) {
        return -1;
    }

    memcpy(ethh->h_source, get_dev_mac_addr("br-lan"), sizeof(ethh->h_source));//UDP needed??
    memcpy(ethh->h_dest, tdev->mac_addr, sizeof(ethh->h_dest));

    iph = ip_hdr(skb);
    if (iph == NULL) {
         return -1;
    }

    iph->daddr = tdev->ip_addr;

    return 0;
}

static int send_pkt(struct sk_buff *skb)
{
    //print_pkt_info(skb);
    skb_push(skb, ETH_HLEN);
    if (dev_queue_xmit(skb) < 0) {
        printk("===forward fail in dev:%s==\n", skb->dev->name);
        return -1;
    }
    return 0;
}

static __be32 get_dev_ip_addr(struct sk_buff *skb)
{
    struct in_device *in_dev = NULL;
    __be32 addr = 0;

    if (skb->dev == NULL) {
        return 0;
    }

    rcu_read_lock();
    in_dev = __in_dev_get_rcu(skb->dev);
    if (in_dev != NULL) {
        for_primary_ifa(in_dev) {
            if (!ipv4_is_loopback(ifa->ifa_local)) {
                addr = ifa->ifa_local;
                break;
            }
        } endfor_ifa(in_dev);
    }
    rcu_read_unlock();
    return addr;
}

static int is_my_ip(struct sk_buff *skb, __be32 ip)
{
    struct in_device *in_dev = NULL;
    int ret = 0;

    if (skb->dev == NULL) {
        return 0;
    }

    rcu_read_lock();
    in_dev = __in_dev_get_rcu(skb->dev);
    if (in_dev != NULL) {
        for_primary_ifa(in_dev) {
            if (ifa->ifa_local == ip) {
                ret = 1;
                break;
            }
        } endfor_ifa(in_dev);
    }
    rcu_read_unlock();

    return ret;

}


static void set_up_router_mac(unsigned char *mac)
{
    memcpy(up_router_mac, mac, sizeof(up_router_mac));
}

static int handle_host_tcp_pkt(struct sk_buff *skb)
{
    struct ethhdr *ethh;

    printk("======receviev packet from host=======\n");

    ethh = eth_hdr(skb);
    set_up_router_mac(ethh->h_source);  //记录面板路由器的MAC地址

    return NF_ACCEPT;
}


static int handle_room_tcp_pkt(struct sk_buff *skb)
{
    struct sk_buff *pskb;

    pskb = skb_copy(skb, GFP_ATOMIC);
    if (pskb == NULL) {
        return NF_DROP;
    }

    //修改源IP与源MAC为智能路由器，并且修改目的MAC为面板路由器
    memcpy(beebox.mac_addr, get_dev_mac_addr("br-lan"), sizeof(beebox.mac_addr));
    if (mangle_src_addr(pskb, &beebox) < 0) {
        goto out;
    }

    if (do_check_sum(pskb) < 0) {
        goto out;
    }

    if (send_pkt(pskb) < 0) {
        dev_put(pskb->dev);
        goto out;
    }

    return NF_STOLEN;
out:
    kfree_skb(pskb);
    return NF_DROP;
}

static int is_from_door(struct sk_buff *skb, __be32 ip)
{
    return is_my_ip(skb, ip);
}

static int is_up_router_set(struct ethhdr *ethh)
{
    unsigned char init_mac[6] = {0};
    return !memcmp(ethh->h_source, init_mac, sizeof(ethh->h_source));
}

static int handle_udp_pkt(struct sk_buff *skb)
{
    struct ethhdr *ethh;
    struct sk_buff *pskb;
    struct iphdr *iph;
    struct udphdr *udph;
    int dst_port = 0;

    iph = ip_hdr(skb);
    udph = (struct udphdr *)((__u32 *)iph + iph->ihl);
    dst_port = ntohs(udph->dest);
    if (dst_port != VIDEO_PORT && dst_port != AUDIO_PORT &&
        dst_port != ALARM_SEND_PORT && dst_port != ALARM_RCV_PORT) {
        return NF_ACCEPT;
    }

    pskb = skb_copy(skb, GFP_ATOMIC);
    if (pskb == NULL) {
        return NF_DROP;
    }

    //TODO: check
    if (is_from_door(pskb, iph->daddr)) {
        ethh = eth_hdr(pskb);

        if (is_up_router_set(ethh)) {
            set_up_router_mac(ethh->h_source);
        }

        if (mangle_dst_addr(pskb, &reply_dev) < 0) {
            goto out;
        }
    } else {
        memcpy(beebox.mac_addr, get_dev_mac_addr("br-lan"), sizeof(beebox.mac_addr));
        beebox.ip_addr = get_dev_ip_addr(pskb);
        if (mangle_src_addr(pskb, &beebox) < 0) {
            goto out;
        }
    }

    if (do_check_sum(pskb) < 0) {
        goto out;
    }

    if (send_pkt(pskb) < 0) {
        dev_put(pskb->dev);
        goto out;
    }

    return NF_STOLEN;
out:
    kfree_skb(pskb);
    return NF_DROP;
}

unsigned int dac_forward_handler(const struct nf_hook_ops *ops,
                        struct sk_buff *_skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;

    iph = ip_hdr(_skb);
    if (iph == NULL) {
         return NF_ACCEPT;
    }

    switch (iph->protocol) {
        #if 0
        case IPPROTO_TCP:
            struct tcphdr *tcph;
            print_pkt_info(_skb);
            tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
            if (ntohs(tcph->dest) == CTL_PORT && iph->daddr == in_aton("192.168.1.1")) {
                return handle_host_tcp_pkt(_skb);
            } else if (ntohs(tcph->source) == CTL_PORT && iph->daddr != in_aton("192.168.1.1")) {
                return handle_room_tcp_pkt(_skb);
            }
            break;
        #endif
        case IPPROTO_UDP:
            //print_pkt_info(_skb);
            return handle_udp_pkt(_skb);
        default:
            break;
    }
    return NF_ACCEPT;
}

static void dac_netlink_rcv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    struct target_dev *tdev = NULL;

    if (skb->len >= nlmsg_total_size(0)) {
        nlh = nlmsg_hdr(skb);

        tdev = (struct target_dev *)NLMSG_DATA(nlh);
        if (tdev) {
            printk("mac: %pM, ip: %pI4\n", tdev->mac_addr, &tdev->ip_addr);
            memcpy(&reply_dev, tdev, sizeof(reply_dev));
        }
    }
}

static int dac_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input	= dac_netlink_rcv,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_DAC, &cfg);
	if (!nl_sk) {
		return -ENOMEM;
	}

	return 0;
}

static void dac_netlink_exit(void)
{
	netlink_kernel_release(nl_sk);
}


static struct nf_hook_ops dac_forward_hook_ops = {
	.hook	=	dac_forward_handler,
	.owner	=	THIS_MODULE,
	.pf		=	PF_BRIDGE,
	.hooknum =	NF_BR_PRE_ROUTING,
	.priority =	NF_BR_PRI_FIRST,
};

static void init_target_dev(void)
{
    memset(up_router_mac, 0, sizeof(up_router_mac));
    beebox.ip_addr = in_aton("192.168.1.1");
    memset(&reply_dev, 0, sizeof(reply_dev));
}

static int __init dac_forward_init(void)
{
	int ret = 0;
    printk("===dac_forward_init\n");

    init_target_dev();

    ret = dac_netlink_init();
    if (ret < 0) {
        return -1;
    }

	ret = nf_register_hook(&dac_forward_hook_ops);
    if (ret < 0) {
        printk ("some error occurred when init module dac_forward!\n");
        dac_netlink_exit();
	}

	return ret;
}

static void __exit dac_forward_exit(void)
{
    printk("===dac_forward_exit\n");
	nf_unregister_hook(&dac_forward_hook_ops);
    dac_netlink_exit();
	return;
}

module_init(dac_forward_init);
module_exit(dac_forward_exit);
