// SPDX-License-Identifier: GPL-2.0
/*
 * IPv6 Address Label subsystem
 * for the IPv6 "Default" Source Address Selection
 *
 * Copyright (C)2007 USAGI/WIDE Project
 */
/*
 * Author:
 *	YOSHIFUJI Hideaki @ USAGI/WIDE Project <yoshfuji@linux-ipv6.org>
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <net/addrconf.h>
#include <linux/if_addrlabel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/*
 * Policy Table
 */
struct ip6addrlbl_entry {
	struct in6_addr prefix;
	int prefixlen;
	int ifindex;
	int addrtype;
	u32 label;
	u32 precedence;
	u8 protocol;
	struct hlist_node list;
	struct rcu_head rcu;
};

/*
 * Default policy table (RFC6724 + extensions)
 *
 * prefix		addr_type	label	precedence
 * -------------------------------------------------------------------------
 * ::1/128		LOOPBACK	0	50
 * ::/0			N/A		1	40
 * 2002::/16		N/A		2	5
 * ::/96		COMPATv4	3	1
 * ::ffff:0:0/96	V4MAPPED	4	20
 * fc00::/7		N/A		5	30	ULA (RFC 4193)
 * 2001::/32		N/A		6	5	Teredo (RFC 4380)
 * 2001:10::/28		N/A		7	-	ORCHID (RFC 4843)
 * fec0::/10		N/A		11	1	Site-local
 *							(deprecated by RFC3879)
 * 3ffe::/16		N/A		12	1	6bone
 *
 * Note: 0xffffffff is used if we do not have any policies.
 * Note: Labels for ULA and 6to4 are different from labels listed in RFC6724.
 * Note: The precedences are the ones updated by
 *	 draft-ietf-6man-rfc6724-update. The kernel does not use them itself,
 *	 they are exported for destination address selection in userspace.
 * Note: An entry for all interfaces added without a precedence for one of
 *	 these prefixes gets the precedence listed here, so that changing
 *	 only the label of e.g. ::/0 leaves its precedence alone.
 */

#define IPV6_ADDR_LABEL_DEFAULT	0xffffffffUL
#define IPV6_ADDR_PRECEDENCE_NONE	0xffffffffUL

static const struct ip6addrlbl_init_table
{
	const struct in6_addr *prefix;
	int prefixlen;
	u32 label;
	u32 precedence;
} ip6addrlbl_init_table[] = {
	{	/* ::/0 */
		.prefix = &in6addr_any,
		.label = 1,
		.precedence = 40,
	}, {	/* fc00::/7 */
		.prefix = &(struct in6_addr){ { { 0xfc } } } ,
		.prefixlen = 7,
		.label = 5,
		.precedence = 30,
	}, {	/* fec0::/10 */
		.prefix = &(struct in6_addr){ { { 0xfe, 0xc0 } } },
		.prefixlen = 10,
		.label = 11,
		.precedence = 1,
	}, {	/* 2002::/16 */
		.prefix = &(struct in6_addr){ { { 0x20, 0x02 } } },
		.prefixlen = 16,
		.label = 2,
		.precedence = 5,
	}, {	/* 3ffe::/16 */
		.prefix = &(struct in6_addr){ { { 0x3f, 0xfe } } },
		.prefixlen = 16,
		.label = 12,
		.precedence = 1,
	}, {	/* 2001::/32 */
		.prefix = &(struct in6_addr){ { { 0x20, 0x01 } } },
		.prefixlen = 32,
		.label = 6,
		.precedence = 5,
	}, {	/* 2001:10::/28 */
		.prefix = &(struct in6_addr){ { { 0x20, 0x01, 0x00, 0x10 } } },
		.prefixlen = 28,
		.label = 7,
		.precedence = IPV6_ADDR_PRECEDENCE_NONE,
	}, {	/* ::ffff:0:0 */
		.prefix = &(struct in6_addr){ { { [10] = 0xff, [11] = 0xff } } },
		.prefixlen = 96,
		.label = 4,
		.precedence = 20,
	}, {	/* ::/96 */
		.prefix = &in6addr_any,
		.prefixlen = 96,
		.label = 3,
		.precedence = 1,
	}, {	/* ::1/128 */
		.prefix = &in6addr_loopback,
		.prefixlen = 128,
		.label = 0,
		.precedence = 50,
	}
};

/* Find label */
static bool __ip6addrlbl_match(const struct ip6addrlbl_entry *p,
			       const struct in6_addr *addr,
			       int addrtype, int ifindex)
{
	if (p->ifindex && p->ifindex != ifindex)
		return false;
	if (p->addrtype && p->addrtype != addrtype)
		return false;
	if (!ipv6_prefix_equal(addr, &p->prefix, p->prefixlen))
		return false;
	return true;
}

static struct ip6addrlbl_entry *__ipv6_addr_label(struct net *net,
						  const struct in6_addr *addr,
						  int type, int ifindex)
{
	struct ip6addrlbl_entry *p;

	hlist_for_each_entry_rcu(p, &net->ipv6.ip6addrlbl_table.head, list) {
		if (__ip6addrlbl_match(p, addr, type, ifindex))
			return p;
	}
	return NULL;
}

u32 ipv6_addr_label(struct net *net,
		    const struct in6_addr *addr, int type, int ifindex)
{
	u32 label;
	struct ip6addrlbl_entry *p;

	type &= IPV6_ADDR_MAPPED | IPV6_ADDR_COMPATv4 | IPV6_ADDR_LOOPBACK;

	rcu_read_lock();
	p = __ipv6_addr_label(net, addr, type, ifindex);
	label = p ? p->label : IPV6_ADDR_LABEL_DEFAULT;
	rcu_read_unlock();

	net_dbg_ratelimited("%s(addr=%pI6, type=%d, ifindex=%d) => %08x\n", __func__, addr, type,
			    ifindex, label);

	return label;
}

/* allocate one entry */
static struct ip6addrlbl_entry *ip6addrlbl_alloc(const struct in6_addr *prefix,
						 int prefixlen, int ifindex,
						 u32 label, u32 precedence,
						 u8 protocol)
{
	struct ip6addrlbl_entry *newp;
	int addrtype;

	net_dbg_ratelimited("%s(prefix=%pI6, prefixlen=%d, ifindex=%d, label=%u)\n", __func__,
			    prefix, prefixlen, ifindex, (unsigned int)label);

	addrtype = ipv6_addr_type(prefix) & (IPV6_ADDR_MAPPED | IPV6_ADDR_COMPATv4 | IPV6_ADDR_LOOPBACK);

	switch (addrtype) {
	case IPV6_ADDR_MAPPED:
		if (prefixlen > 96)
			return ERR_PTR(-EINVAL);
		if (prefixlen < 96)
			addrtype = 0;
		break;
	case IPV6_ADDR_COMPATv4:
		if (prefixlen != 96)
			addrtype = 0;
		break;
	case IPV6_ADDR_LOOPBACK:
		if (prefixlen != 128)
			addrtype = 0;
		break;
	}

	newp = kmalloc_obj(*newp);
	if (!newp)
		return ERR_PTR(-ENOMEM);

	ipv6_addr_prefix(&newp->prefix, prefix, prefixlen);
	newp->prefixlen = prefixlen;
	newp->ifindex = ifindex;
	newp->addrtype = addrtype;
	newp->label = label;
	newp->precedence = precedence;
	newp->protocol = protocol;
	INIT_HLIST_NODE(&newp->list);
	return newp;
}

/* add a label */
static int __ip6addrlbl_add(struct net *net, struct ip6addrlbl_entry *newp,
			    int replace)
{
	struct ip6addrlbl_entry *last = NULL, *p = NULL;
	int ret = 0;

	net_dbg_ratelimited("%s(newp=%p, replace=%d)\n", __func__, newp, replace);

	/* An entry with the same key may come after other entries with the
	 * same prefix length, hence look for it before finding the insertion
	 * point.
	 */
	hlist_for_each_entry(p, &net->ipv6.ip6addrlbl_table.head, list) {
		if (p->prefixlen == newp->prefixlen &&
		    p->ifindex == newp->ifindex &&
		    ipv6_addr_equal(&p->prefix, &newp->prefix)) {
			if (!replace) {
				ret = -EEXIST;
				goto out;
			}
			hlist_replace_rcu(&p->list, &newp->list);
			kfree_rcu(p, rcu);
			goto out;
		}
	}

	hlist_for_each_entry(p, &net->ipv6.ip6addrlbl_table.head, list) {
		if ((p->prefixlen == newp->prefixlen && !p->ifindex) ||
		    (p->prefixlen < newp->prefixlen)) {
			hlist_add_before_rcu(&newp->list, &p->list);
			goto out;
		}
		last = p;
	}
	if (last)
		hlist_add_behind_rcu(&newp->list, &last->list);
	else
		hlist_add_head_rcu(&newp->list, &net->ipv6.ip6addrlbl_table.head);
out:
	if (!ret)
		WRITE_ONCE(net->ipv6.ip6addrlbl_table.seq,
			   net->ipv6.ip6addrlbl_table.seq + 1);
	return ret;
}

/* add a label */
static int ip6addrlbl_add(struct net *net,
			  const struct in6_addr *prefix, int prefixlen,
			  int ifindex, u32 label, u32 precedence, u8 protocol,
			  int replace)
{
	struct ip6addrlbl_entry *newp;
	int ret = 0;

	net_dbg_ratelimited("%s(prefix=%pI6, prefixlen=%d, ifindex=%d, label=%u, replace=%d)\n",
			    __func__, prefix, prefixlen, ifindex, (unsigned int)label, replace);

	newp = ip6addrlbl_alloc(prefix, prefixlen, ifindex, label, precedence,
				protocol);
	if (IS_ERR(newp))
		return PTR_ERR(newp);
	spin_lock(&net->ipv6.ip6addrlbl_table.lock);
	ret = __ip6addrlbl_add(net, newp, replace);
	spin_unlock(&net->ipv6.ip6addrlbl_table.lock);
	if (ret)
		kfree(newp);
	return ret;
}

/* remove a label */
static int __ip6addrlbl_del(struct net *net,
			    const struct in6_addr *prefix, int prefixlen,
			    int ifindex, u8 protocol)
{
	struct ip6addrlbl_entry *p = NULL;
	struct hlist_node *n;
	int ret = -ESRCH;

	net_dbg_ratelimited("%s(prefix=%pI6, prefixlen=%d, ifindex=%d)\n", __func__, prefix,
			    prefixlen, ifindex);

	hlist_for_each_entry_safe(p, n, &net->ipv6.ip6addrlbl_table.head, list) {
		if (p->prefixlen == prefixlen &&
		    p->ifindex == ifindex &&
		    ipv6_addr_equal(&p->prefix, prefix)) {
			if (protocol && p->protocol != protocol)
				break;
			hlist_del_rcu(&p->list);
			WRITE_ONCE(net->ipv6.ip6addrlbl_table.seq,
				   net->ipv6.ip6addrlbl_table.seq + 1);
			kfree_rcu(p, rcu);
			ret = 0;
			break;
		}
	}
	return ret;
}

/* Only remove an entry of @protocol, if not 0 */
static int ip6addrlbl_del(struct net *net,
			  const struct in6_addr *prefix, int prefixlen,
			  int ifindex, u8 protocol)
{
	struct in6_addr prefix_buf;
	int ret;

	net_dbg_ratelimited("%s(prefix=%pI6, prefixlen=%d, ifindex=%d)\n", __func__, prefix,
			    prefixlen, ifindex);

	ipv6_addr_prefix(&prefix_buf, prefix, prefixlen);
	spin_lock(&net->ipv6.ip6addrlbl_table.lock);
	ret = __ip6addrlbl_del(net, &prefix_buf, prefixlen, ifindex,
			       protocol);
	spin_unlock(&net->ipv6.ip6addrlbl_table.lock);
	return ret;
}

/* add default label */
static int __net_init ip6addrlbl_net_init(struct net *net)
{
	struct ip6addrlbl_entry *p = NULL;
	struct hlist_node *n;
	int err;
	int i;

	spin_lock_init(&net->ipv6.ip6addrlbl_table.lock);
	INIT_HLIST_HEAD(&net->ipv6.ip6addrlbl_table.head);

	for (i = 0; i < ARRAY_SIZE(ip6addrlbl_init_table); i++) {
		err = ip6addrlbl_add(net,
				     ip6addrlbl_init_table[i].prefix,
				     ip6addrlbl_init_table[i].prefixlen,
				     0,
				     ip6addrlbl_init_table[i].label,
				     ip6addrlbl_init_table[i].precedence,
				     RTPROT_KERNEL, 0);
		if (err)
			goto err_ip6addrlbl_add;
	}
	return 0;

err_ip6addrlbl_add:
	hlist_for_each_entry_safe(p, n, &net->ipv6.ip6addrlbl_table.head, list) {
		hlist_del_rcu(&p->list);
		kfree_rcu(p, rcu);
	}
	return err;
}

static void __net_exit ip6addrlbl_net_exit(struct net *net)
{
	struct ip6addrlbl_entry *p = NULL;
	struct hlist_node *n;

	/* Remove all labels belonging to the exiting net */
	spin_lock(&net->ipv6.ip6addrlbl_table.lock);
	hlist_for_each_entry_safe(p, n, &net->ipv6.ip6addrlbl_table.head, list) {
		hlist_del_rcu(&p->list);
		kfree_rcu(p, rcu);
	}
	spin_unlock(&net->ipv6.ip6addrlbl_table.lock);
}

static struct pernet_operations ipv6_addr_label_ops = {
	.init = ip6addrlbl_net_init,
	.exit = ip6addrlbl_net_exit,
};

int __init ipv6_addr_label_init(void)
{
	return register_pernet_subsys(&ipv6_addr_label_ops);
}

void ipv6_addr_label_cleanup(void)
{
	unregister_pernet_subsys(&ipv6_addr_label_ops);
}

static const struct netlink_range_validation ifal_precedence_range = {
	.max = IPV6_ADDR_PRECEDENCE_NONE - 1,
};

static const struct nla_policy ifal_policy[IFAL_MAX+1] = {
	[0]			= { .strict_start_type = IFAL_PRECEDENCE },
	[IFAL_ADDRESS]		= { .len = sizeof(struct in6_addr), },
	[IFAL_LABEL]		= { .len = sizeof(u32), },
	[IFAL_PRECEDENCE]	= NLA_POLICY_FULL_RANGE(NLA_U32,
							&ifal_precedence_range),
	[IFAL_PROTOCOL]		= { .type = NLA_U8 },
};

/* The precedence of a new entry without IFAL_PRECEDENCE: that of the same
 * prefix in the default table, unless the entry is for a single interface.
 */
static u32 ip6addrlbl_default_precedence(const struct ifaddrlblmsg *ifal,
					 const struct in6_addr *prefix)
{
	int plen = ifal->ifal_prefixlen;
	int i;

	if (ifal->ifal_index)
		return IPV6_ADDR_PRECEDENCE_NONE;

	for (i = 0; i < ARRAY_SIZE(ip6addrlbl_init_table); i++) {
		if (ip6addrlbl_init_table[i].prefixlen == plen &&
		    ipv6_prefix_equal(ip6addrlbl_init_table[i].prefix, prefix,
				      plen))
			return ip6addrlbl_init_table[i].precedence;
	}

	return IPV6_ADDR_PRECEDENCE_NONE;
}

static bool addrlbl_ifindex_exists(struct net *net, int ifindex)
{

	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifindex);
	rcu_read_unlock();

	return dev != NULL;
}

static int ip6addrlbl_newdel(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct ifaddrlblmsg *ifal;
	struct nlattr *tb[IFAL_MAX+1];
	u32 precedence = IPV6_ADDR_PRECEDENCE_NONE;
	struct in6_addr *pfx;
	u8 protocol;
	u32 label;
	int err = 0;

	err = nlmsg_parse_deprecated(nlh, sizeof(*ifal), tb, IFAL_MAX,
				     ifal_policy, extack);
	if (err < 0)
		return err;

	ifal = nlmsg_data(nlh);

	if (ifal->ifal_family != AF_INET6 ||
	    ifal->ifal_prefixlen > 128)
		return -EINVAL;

	if (!tb[IFAL_ADDRESS])
		return -EINVAL;
	pfx = nla_data(tb[IFAL_ADDRESS]);

	if (!tb[IFAL_LABEL])
		return -EINVAL;
	label = nla_get_u32(tb[IFAL_LABEL]);
	if (label == IPV6_ADDR_LABEL_DEFAULT)
		return -EINVAL;

	protocol = nla_get_u8_default(tb[IFAL_PROTOCOL], RTPROT_UNSPEC);

	switch (nlh->nlmsg_type) {
	case RTM_NEWADDRLABEL:
		if (ifal->ifal_index &&
		    !addrlbl_ifindex_exists(net, ifal->ifal_index))
			return -EINVAL;

		if (tb[IFAL_PRECEDENCE])
			precedence = nla_get_u32(tb[IFAL_PRECEDENCE]);
		else
			precedence = ip6addrlbl_default_precedence(ifal, pfx);

		err = ip6addrlbl_add(net, pfx, ifal->ifal_prefixlen,
				     ifal->ifal_index, label, precedence,
				     protocol,
				     nlh->nlmsg_flags & NLM_F_REPLACE);
		break;
	case RTM_DELADDRLABEL:
		err = ip6addrlbl_del(net, pfx, ifal->ifal_prefixlen,
				     ifal->ifal_index, protocol);
		break;
	default:
		err = -EOPNOTSUPP;
	}
	return err;
}

static void ip6addrlbl_putmsg(struct nlmsghdr *nlh,
			      int prefixlen, int ifindex, u32 lseq)
{
	struct ifaddrlblmsg *ifal = nlmsg_data(nlh);
	ifal->ifal_family = AF_INET6;
	ifal->__ifal_reserved = 0;
	ifal->ifal_prefixlen = prefixlen;
	ifal->ifal_flags = 0;
	ifal->ifal_index = ifindex;
	ifal->ifal_seq = lseq;
};

static int ip6addrlbl_fill(struct sk_buff *skb,
			   const struct ip6addrlbl_entry *p,
			   u32 lseq,
			   u32 portid, u32 seq, int event,
			   unsigned int flags)
{
	struct nlmsghdr *nlh = nlmsg_put(skb, portid, seq, event,
					 sizeof(struct ifaddrlblmsg), flags);
	if (!nlh)
		return -EMSGSIZE;

	ip6addrlbl_putmsg(nlh, p->prefixlen, p->ifindex, lseq);

	if (nla_put_in6_addr(skb, IFAL_ADDRESS, &p->prefix) < 0 ||
	    nla_put_u32(skb, IFAL_LABEL, p->label) < 0 ||
	    (p->precedence != IPV6_ADDR_PRECEDENCE_NONE &&
	     nla_put_u32(skb, IFAL_PRECEDENCE, p->precedence) < 0) ||
	    (p->protocol && nla_put_u8(skb, IFAL_PROTOCOL, p->protocol) < 0)) {
		nlmsg_cancel(skb, nlh);
		return -EMSGSIZE;
	}

	nlmsg_end(skb, nlh);
	return 0;
}

static int ip6addrlbl_valid_dump_req(const struct nlmsghdr *nlh,
				     struct netlink_ext_ack *extack)
{
	struct ifaddrlblmsg *ifal;

	ifal = nlmsg_payload(nlh, sizeof(*ifal));
	if (!ifal) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid header for address label dump request");
		return -EINVAL;
	}

	if (ifal->__ifal_reserved || ifal->ifal_prefixlen ||
	    ifal->ifal_flags || ifal->ifal_index || ifal->ifal_seq) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid values in header for address label dump request");
		return -EINVAL;
	}

	if (nlmsg_attrlen(nlh, sizeof(*ifal))) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid data after header for address label dump request");
		return -EINVAL;
	}

	return 0;
}

static int ip6addrlbl_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct nlmsghdr *nlh = cb->nlh;
	struct net *net = sock_net(skb->sk);
	struct ip6addrlbl_entry *p;
	int idx = 0, s_idx = cb->args[0];
	int err = 0;
	u32 lseq;

	if (cb->strict_check) {
		err = ip6addrlbl_valid_dump_req(nlh, cb->extack);
		if (err < 0)
			return err;
	}

	rcu_read_lock();
	lseq = READ_ONCE(net->ipv6.ip6addrlbl_table.seq);
	cb->seq = lseq ?: 1;
	hlist_for_each_entry_rcu(p, &net->ipv6.ip6addrlbl_table.head, list) {
		if (idx >= s_idx) {
			err = ip6addrlbl_fill(skb, p,
					      lseq,
					      NETLINK_CB(cb->skb).portid,
					      nlh->nlmsg_seq,
					      RTM_NEWADDRLABEL,
					      NLM_F_MULTI);
			if (err < 0)
				break;
			nl_dump_check_consistent(cb, nlmsg_hdr(skb));
		}
		idx++;
	}
	rcu_read_unlock();
	cb->args[0] = idx;
	return err;
}

static inline int ip6addrlbl_msgsize(void)
{
	return NLMSG_ALIGN(sizeof(struct ifaddrlblmsg))
		+ nla_total_size(16)	/* IFAL_ADDRESS */
		+ nla_total_size(4)	/* IFAL_LABEL */
		+ nla_total_size(4)	/* IFAL_PRECEDENCE */
		+ nla_total_size(1);	/* IFAL_PROTOCOL */
}

static int ip6addrlbl_valid_get_req(struct sk_buff *skb,
				    const struct nlmsghdr *nlh,
				    struct nlattr **tb,
				    struct netlink_ext_ack *extack)
{
	struct ifaddrlblmsg *ifal;
	int i, err;

	ifal = nlmsg_payload(nlh, sizeof(*ifal));
	if (!ifal) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid header for addrlabel get request");
		return -EINVAL;
	}

	if (!netlink_strict_get_check(skb))
		return nlmsg_parse_deprecated(nlh, sizeof(*ifal), tb,
					      IFAL_MAX, ifal_policy, extack);

	if (ifal->__ifal_reserved || ifal->ifal_flags || ifal->ifal_seq) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid values in header for addrlabel get request");
		return -EINVAL;
	}

	err = nlmsg_parse_deprecated_strict(nlh, sizeof(*ifal), tb, IFAL_MAX,
					    ifal_policy, extack);
	if (err)
		return err;

	for (i = 0; i <= IFAL_MAX; i++) {
		if (!tb[i])
			continue;

		switch (i) {
		case IFAL_ADDRESS:
			break;
		default:
			NL_SET_ERR_MSG_MOD(extack, "Unsupported attribute in addrlabel get request");
			return -EINVAL;
		}
	}

	return 0;
}

static int ip6addrlbl_get(struct sk_buff *in_skb, struct nlmsghdr *nlh,
			  struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(in_skb->sk);
	struct ifaddrlblmsg *ifal;
	struct nlattr *tb[IFAL_MAX+1];
	struct in6_addr *addr;
	u32 lseq;
	int err = 0;
	struct ip6addrlbl_entry *p;
	struct sk_buff *skb;

	err = ip6addrlbl_valid_get_req(in_skb, nlh, tb, extack);
	if (err < 0)
		return err;

	ifal = nlmsg_data(nlh);

	if (ifal->ifal_family != AF_INET6 ||
	    ifal->ifal_prefixlen != 128)
		return -EINVAL;

	if (ifal->ifal_index &&
	    !addrlbl_ifindex_exists(net, ifal->ifal_index))
		return -EINVAL;

	if (!tb[IFAL_ADDRESS])
		return -EINVAL;
	addr = nla_data(tb[IFAL_ADDRESS]);

	skb = nlmsg_new(ip6addrlbl_msgsize(), GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	err = -ESRCH;

	rcu_read_lock();
	p = __ipv6_addr_label(net, addr, ipv6_addr_type(addr), ifal->ifal_index);
	lseq = READ_ONCE(net->ipv6.ip6addrlbl_table.seq);
	if (p)
		err = ip6addrlbl_fill(skb, p, lseq,
				      NETLINK_CB(in_skb).portid,
				      nlh->nlmsg_seq,
				      RTM_NEWADDRLABEL, 0);
	rcu_read_unlock();

	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
	} else {
		err = rtnl_unicast(skb, net, NETLINK_CB(in_skb).portid);
	}
	return err;
}

static const struct rtnl_msg_handler ipv6_adddr_label_rtnl_msg_handlers[] __initconst_or_module = {
	{.owner = THIS_MODULE, .protocol = PF_INET6, .msgtype = RTM_NEWADDRLABEL,
	 .doit = ip6addrlbl_newdel, .flags = RTNL_FLAG_DOIT_UNLOCKED},
	{.owner = THIS_MODULE, .protocol = PF_INET6, .msgtype = RTM_DELADDRLABEL,
	 .doit = ip6addrlbl_newdel, .flags = RTNL_FLAG_DOIT_UNLOCKED},
	{.owner = THIS_MODULE, .protocol = PF_INET6, .msgtype = RTM_GETADDRLABEL,
	 .doit = ip6addrlbl_get, .dumpit = ip6addrlbl_dump,
	 .flags = RTNL_FLAG_DOIT_UNLOCKED | RTNL_FLAG_DUMP_UNLOCKED},
};

int __init ipv6_addr_label_rtnl_register(void)
{
	return rtnl_register_many(ipv6_adddr_label_rtnl_msg_handlers);
}
