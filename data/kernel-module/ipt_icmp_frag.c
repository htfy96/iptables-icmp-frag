#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ipt_icmp_frag.h"

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/icmp.h>
#include <net/ip.h>
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#include <linux/netfilter_bridge.h>
#endif


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vic Luo <vicluo96@gmail.com");
MODULE_DESCRIPTION("Xtables: packet \"icmp_frag\" target for IPv4");

static void icmp_send_frag(struct sk_buff *skb_in, int hook, __u16 mtu)
{
	struct iphdr *iph = ip_hdr(skb_in);
    struct icmphdr hdr = {};
	u8 proto = iph->protocol;

	if (iph->frag_off & htons(IP_OFFSET))
		return;

    hdr.un.frag.mtu = cpu_to_be16(mtu);

	if (skb_csum_unnecessary(skb_in)) {
		icmp_send(skb_in, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, hdr.un.gateway);
		return;
	}

	if (nf_ip_checksum(skb_in, hook, ip_hdrlen(skb_in), proto) == 0)
		icmp_send(skb_in, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, hdr.un.gateway);
}

static unsigned int
icmp_frag_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipt_icmp_frag_info *reject = par->targinfo;
	int hook = xt_hooknum(par);
    icmp_send_frag(skb, hook, reject->mcu);

	return NF_DROP;
}

static int icmp_frag_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_icmp_frag_info *fraginfo = par->targinfo;

	if (fraginfo->mcu == 0) {
		pr_info_ratelimited("MTU cannot be zero");
		return -EINVAL;
    }
	return 0;
}

static struct xt_target icmp_frag_tg_reg __read_mostly = {
	.name		= "icmp_frag",
	.family		= NFPROTO_IPV4,
	.target		= icmp_frag_tg,
	.targetsize	= sizeof(struct ipt_icmp_frag_info),
	.table		= "filter",
	.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) |
			  (1 << NF_INET_LOCAL_OUT),
	.checkentry	= icmp_frag_tg_check,
	.me		= THIS_MODULE,
};

static int __init reject_tg_init(void)
{
	return xt_register_target(&icmp_frag_tg_reg);
}

static void __exit reject_tg_exit(void)
{
	xt_unregister_target(&icmp_frag_tg_reg);
}

module_init(reject_tg_init);
module_exit(reject_tg_exit);
