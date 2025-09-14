#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops ops_pre, ops_out;

static unsigned int hook_fn(void *priv, struct sk_buff *skb,
			    const struct nf_hook_state *state) {
  const struct iphdr *iph = ip_hdr(skb);
  if (!iph) return NF_ACCEPT;
  return NF_ACCEPT;
}

static int __init nfmini_init(void)
{
  int ret;
  ops_pre.hook     = hook_fn;
  ops_pre.pf       = PF_INET;
  ops_pre.hooknum  = NF_INET_PRE_ROUTING;
  ops_pre.priority = NF_IP_PRI_FIRST;

  ops_out = ops_pre;
  ops_out.hooknum = NF_INET_LOCAL_OUT;

  ret = nf_register_net_hook(&init_net, &ops_pre);
  if (ret) return ret;
  ret = nf_register_net_hook(&init_net, &ops_out);
  if (ret) {
    nf_unregister_net_hook(&init_net, &ops_pre);
    return ret;
  }
  pr_info("nf-mini-qos loaded\n");
  return 0;
}

static void __exit nfmini_exit(void)
{
  nf_unregister_net_hook(&init_net, &ops_out);
  nf_unregister_net_hook(&init_net, &ops_pre);
  pr_info("nf-mini-qos unloaded\n");
}

module_init(nfmini_init);
module_exit(nfmini_exit);
MODULE_LICENSE("GPL");
