#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import errno
import json
import os
import socket
import struct
import time
from lib.py import bkg, ip, ksft_exit, ksft_run, ksft_eq, ksft_ge, ksft_true, KsftSkipEx
from lib.py import ksft_busy_wait, ksft_in, ksft_not_in, ksft_not_none
from lib.py import CmdExitFailure, NetNS, NetNSEnter, RtnlAddrFamily, RtnlRouteFamily
from lib.py import Netlink, defer

IPV4_ALL_HOSTS_MULTICAST = b'\xe0\x00\x00\x01'
IPV4_TEST_MULTICAST = b'\xef\x01\x01\x01'
IPV6_TEST_MULTICAST = bytes.fromhex('ff020000000000000000000000000123')


def _users_for(rtnl: RtnlAddrFamily, family: int, grp: bytes, ifindex: int):
    """Return mc-users for grp on ifindex, or 0 if absent."""

    addrs = rtnl.getmulticast({"ifa-family": family}, dump=True)
    matches = [addr for addr in addrs
               if addr['multicast'] == grp and addr['ifa-index'] == ifindex]
    if not matches:
        return 0
    if 'mc-users' not in matches[0]:
        return None

    return matches[0]['mc-users']


def dump_mcaddr_check() -> None:
    """
    Verify IPv4 multicast addresses and their user counts in RTM_GETMULTICAST.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            ip("link set lo up")
            rtnl = RtnlAddrFamily()
            lo_idx = socket.if_nametoindex('lo')
            addresses = rtnl.getmulticast({"ifa-family": socket.AF_INET}, dump=True)

            all_host_multicasts = [
                addr for addr in addresses
                if addr['multicast'] == IPV4_ALL_HOSTS_MULTICAST
            ]

            ksft_ge(len(all_host_multicasts), 1,
                    "No interface found with the IPv4 all-hosts multicast address")

            mreq = IPV4_TEST_MULTICAST + socket.inet_aton('127.0.0.1')
            before = _users_for(rtnl, socket.AF_INET, IPV4_TEST_MULTICAST, lo_idx)
            if before is None:
                raise KsftSkipEx("kernel does not expose IFA_MC_USERS")

            s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s1.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                s2.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

                after_join = _users_for(rtnl, socket.AF_INET,
                                        IPV4_TEST_MULTICAST, lo_idx)
                if after_join is None:
                    raise KsftSkipEx("kernel does not expose IFA_MC_USERS")
                ksft_eq(after_join - before, 2,
                        f"users delta != 2 after two joins "
                        f"(before={before}, after={after_join})")
            finally:
                s1.close()
                s2.close()


def dump_mcaddr6_check() -> None:
    """
    Verify IPv6 multicast addresses and their user counts in RTM_GETMULTICAST.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            ip("link set lo up")
            rtnl = RtnlAddrFamily()
            lo_idx = socket.if_nametoindex('lo')
            before = _users_for(rtnl, socket.AF_INET6,
                                IPV6_TEST_MULTICAST, lo_idx)
            if before is None:
                raise KsftSkipEx("kernel does not expose IFA_MC_USERS for IPv6")

            mreq = IPV6_TEST_MULTICAST + struct.pack('=I', lo_idx)
            s1 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                s1.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                s2.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

                after_join = _users_for(rtnl, socket.AF_INET6,
                                        IPV6_TEST_MULTICAST, lo_idx)
                if after_join is None:
                    raise KsftSkipEx("kernel does not expose IFA_MC_USERS for IPv6")
                ksft_eq(after_join - before, 2,
                        f"IPv6 users delta != 2 after two joins "
                        f"(before={before}, after={after_join})")
            finally:
                s1.close()
                s2.close()


def ipv4_devconf_notify() -> None:
    """
    Configure an interface and set ipv4-devconf values through netlink
    to verify that the appropriate netlink notifications are being sent.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            ifname = "dummy1"
            ip(f"link add name {ifname} type dummy", ns=str(ns))

            with bkg("ip monitor", ns=str(ns)) as cmd_obj:
                time.sleep(1)
                try:
                    ip(f"link set dev {ifname} inet forwarding on")
                    ip(f"link set dev {ifname} inet proxy_arp on")
                    ip(f"link set dev {ifname} inet rp_filter 1")
                    ip(f"link set dev {ifname} inet ignore_routes_with_linkdown on")
                except CmdExitFailure:
                    raise KsftSkipEx("iproute2 does not support IPv4 devconf attributes")
                time.sleep(1)

    ksft_true(f"inet {ifname} ignore_routes_with_linkdown on" in cmd_obj.stdout,
              f"No 'ignore_routes_with_linkdown on' notificiation found for interface {ifname}")
    ksft_true(f"inet {ifname} rp_filter strict" in cmd_obj.stdout,
              f"No 'rp_filter strict' notificiation found for interface {ifname}")
    ksft_true(f"inet {ifname} proxy_neigh on" in cmd_obj.stdout,
              f"No 'proxy_neigh on' notificiation found for interface {ifname}")
    ksft_true(f"inet {ifname} forwarding on" in cmd_obj.stdout,
              f"No 'forwarding on' notificiation found for interface {ifname}")

def _rtnl_route_subscribe(ns):
    with NetNSEnter(str(ns)):
        rtnl = RtnlRouteFamily()
    defer(rtnl.close)
    rtnl.ntf_subscribe("rtnlgrp-ipv6-route")
    return rtnl


def _wait_route_ntf(rtnl, name, dst_len, dst=None, deadline=10):
    """Return the attrs of the first matching notification, None on timeout."""

    for msg in rtnl.poll_ntf(duration=deadline):
        if msg['name'] != name:
            continue
        attrs = msg['msg']
        if attrs['rtm-dst-len'] != dst_len:
            continue
        if dst is not None and attrs.get('dst') != dst:
            continue
        return attrs
    return None


def _collect_route_ntfs(rtnl, name, want, deadline=10):
    """Gather attrs of matching notifications, keyed by (dst_len, dst)."""

    seen = {}
    for msg in rtnl.poll_ntf(duration=deadline):
        if msg['name'] != name:
            continue
        attrs = msg['msg']
        key = (attrs['rtm-dst-len'], attrs.get('dst'))
        if key in want:
            seen[key] = attrs
            if len(seen) == len(want):
                break
    return seen


def _write_ipv6_sysctl(name, value):
    with open(f"/proc/sys/net/ipv6/{name}", "w") as f:
        f.write(f"{value}\n")


def ipv6_route_del_reason_expired() -> None:
    """An expired route reports RTA_DEL_REASON == expired."""

    with NetNS() as ns:
        rtnl = _rtnl_route_subscribe(ns)
        with NetNSEnter(str(ns)):
            _write_ipv6_sysctl("route/gc_interval", 2)
        ip("link add name dummy1 type dummy", ns=str(ns))
        ip("link set dev dummy1 up", ns=str(ns))
        ip("-6 route add 2001:db8:2::/64 dev dummy1 expires 2", ns=str(ns))

        attrs = _wait_route_ntf(rtnl, 'delroute-ntf', 64, '2001:db8:2::',
                                deadline=15)
        ksft_not_none(attrs, "no RTM_DELROUTE for the expired route")
        if attrs is not None:
            ksft_eq(attrs.get('del-reason'), 'expired')


def _send_ra(sock, ifindex, lifetime, rio=None, pio=None, pio_flags=0x80,
             ra_flags=0):
    """
    The kernel fills in the ICMPv6 checksum on raw ICMPv6 sockets.
    The PIO is on-link only (L set, A clear) unless pio_flags says otherwise.
    """

    # type, code, cksum, hop limit, flags, router lifetime,
    # reachable time, retrans timer
    ra = struct.pack('!BBHBBHII', 134, 0, 0, 64, ra_flags, lifetime, 0, 0)
    if rio is not None:
        prefix, plen, rio_lifetime = rio
        # RFC 4191 route information option, /64 prefix (8 bytes)
        ra += struct.pack('!BBBBI', 24, 2, plen, 0, rio_lifetime)
        ra += socket.inet_pton(socket.AF_INET6, prefix)[:8]
    if pio is not None:
        prefix, plen, valid_lft = pio
        # RFC 4861 prefix information option
        ra += struct.pack('!BBBBIII', 3, 4, plen, pio_flags, valid_lft,
                          valid_lft, 0)
        ra += socket.inet_pton(socket.AF_INET6, prefix)
    sock.sendto(ra, ('ff02::1', 0, 0, ifindex))


def _ra_router_sock(ns_r, ifname):
    with NetNSEnter(str(ns_r)):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                             socket.IPPROTO_ICMPV6)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        defer(sock.close)
        return sock, socket.if_nametoindex(ifname)


def _ra_advertise_routes(rtnl, sock, ifindex, want, **ra_opts):
    """
    Sending fails with EADDRNOTAVAIL while the router's link-local
    address is still tentative. addrconf_dad_start() only queues
    addrconf_dad_work(), and IFA_F_TENTATIVE is cleared when that work
    item runs, so retry until it does.
    """

    seen = {}
    for _ in range(10):
        try:
            _send_ra(sock, ifindex, **ra_opts)
        except OSError:
            time.sleep(0.2)
            continue
        seen.update(_collect_route_ntfs(rtnl, 'newroute-ntf',
                                        want - set(seen.keys()), deadline=2))
        if len(seen) == len(want):
            break
    return seen


def ipv6_route_del_reason_ra_withdrawn() -> None:
    """
    Routes withdrawn by a zero-lifetime RA (router lifetime, RFC 4861
    PIO, RFC 4191 RIO) report RTA_DEL_REASON == ra-withdrawn.
    """

    # (rtm-dst-len, dst); the default route carries no RTA_DST
    routes = {(0, None), (64, '2001:db8:6::'), (64, '2001:db8:5::')}

    with NetNS() as ns_h, NetNS() as ns_r:
        ip(f"link add veth0 netns {ns_h} type veth peer name veth1 netns {ns_r}")
        with NetNSEnter(str(ns_h)):
            _write_ipv6_sysctl("conf/veth0/accept_ra", 2)
            _write_ipv6_sysctl("conf/veth0/forwarding", 0)
            try:
                _write_ipv6_sysctl("conf/veth0/accept_ra_rt_info_max_plen", 64)
            except FileNotFoundError:
                raise KsftSkipEx("no CONFIG_IPV6_ROUTE_INFO")
        with NetNSEnter(str(ns_r)):
            # skip the DAD probe so the router's link-local source only
            # has to wait for addrconf_dad_work() to clear IFA_F_TENTATIVE
            _write_ipv6_sysctl("conf/veth1/accept_dad", 0)
        ip("link set dev veth0 up", ns=str(ns_h))
        ip("link set dev veth1 up", ns=str(ns_r))

        rtnl = _rtnl_route_subscribe(ns_h)
        sock, ifindex = _ra_router_sock(ns_r, "veth1")

        seen = _ra_advertise_routes(rtnl, sock, ifindex, routes,
                                    lifetime=1800,
                                    rio=('2001:db8:5::', 64, 600),
                                    pio=('2001:db8:6::', 64, 600))
        ksft_eq(set(seen), routes, "not all RA routes were installed")
        if set(seen) != routes:
            return

        _send_ra(sock, ifindex, 0, rio=('2001:db8:5::', 64, 0),
                 pio=('2001:db8:6::', 64, 0))
        seen = _collect_route_ntfs(rtnl, 'delroute-ntf', routes)
        for key in routes:
            attrs = seen.get(key)
            ksft_not_none(attrs, f"no RTM_DELROUTE for {key}")
            if attrs is not None:
                ksft_eq(attrs.get('del-reason'), 'ra-withdrawn')


def ipv6_route_del_reason_absent() -> None:
    """
    A deletion path that records no cause (here a userspace request)
    must not carry RTA_DEL_REASON at all.
    """

    with NetNS() as ns:
        rtnl = _rtnl_route_subscribe(ns)
        ip("link add name dummy1 type dummy", ns=str(ns))
        ip("link set dev dummy1 up", ns=str(ns))
        ip("-6 route add 2001:db8:1::/64 dev dummy1", ns=str(ns))
        ip("-6 route del 2001:db8:1::/64 dev dummy1", ns=str(ns))

        attrs = _wait_route_ntf(rtnl, 'delroute-ntf', 64, '2001:db8:1::')
        ksft_not_none(attrs, "no RTM_DELROUTE for 2001:db8:1::/64")
        if attrs is not None:
            ksft_not_in('del-reason', attrs,
                        "user deletion must not carry del-reason")


def _in6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def _ntop6(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)


def _saddr(daddr):
    """Source address the kernel selects when connecting to daddr."""

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.connect((daddr, 9))
        return sock.getsockname()[0]


def _route_get_saddr(daddr):
    """Source address reported by RTM_GETROUTE for daddr."""

    return ip(f"-6 route get {daddr}", json=True)[0].get('prefsrc')


def _nlattr(atype, value):
    attr = struct.pack('=HH', 4 + len(value), atype) + value
    return attr + b'\0' * (-len(attr) % 4)


def _nlmsgs(data, hdr_len):
    """Parse netlink messages into (type, header, {attr type: payload})."""

    off = 0
    while off < len(data):
        nl_len, nl_type = struct.unpack_from('=IH', data, off)
        hdr = data[off + 16:off + 16 + hdr_len]
        parsed = {}
        aoff = off + 16 + hdr_len
        while nl_type >= 16 and aoff < off + nl_len:
            alen, atype = struct.unpack_from('=HH', data, aoff)
            parsed[atype] = data[aoff + 4:aoff + alen]
            aoff += (alen + 3) & ~3
        yield nl_type, data[off:off + nl_len], hdr, parsed
        off += (nl_len + 3) & ~3


SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NETLINK_GET_STRICT_CHK = 12


def _rtnl_request(msg_type, flags, header, attrs=b'', strict=False):
    """
    Send a raw rtnetlink request, return (errno, replies) where replies are
    (header, {attribute type: payload}) tuples.
    """

    payload = header + attrs
    msg = struct.pack('=IHHII', 16 + len(payload), msg_type,
                      Netlink.NLM_F_REQUEST | flags, 1, 0) + payload
    replies = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                       socket.NETLINK_ROUTE) as sock:
        if strict:
            sock.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
        sock.send(msg)
        while True:
            data = sock.recv(65536)
            for nl_type, raw, hdr, parsed in _nlmsgs(data, len(header)):
                if nl_type == Netlink.NLMSG_DONE:
                    err = 0
                    if len(raw) >= 20:
                        err, = struct.unpack_from('=i', raw, 16)
                    return err, replies
                if nl_type == Netlink.NLMSG_ERROR:
                    err, = struct.unpack_from('=i', raw, 16)
                    return err, replies
                replies.append((hdr, parsed))


def _rtnl_listen(group):
    """Return a netlink socket subscribed to the rtnetlink group."""

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                         socket.NETLINK_ROUTE)
    sock.bind((0, 0))
    sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)
    return sock


def _rtnl_events(sock, hdr_len, count, deadline=5):
    """Return the next count messages received on sock, or fewer on timeout."""

    events = []
    end = time.time() + deadline
    while len(events) < count and time.time() < end:
        sock.settimeout(max(end - time.time(), 0.01))
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        events += [(t, h, a) for t, _, h, a in _nlmsgs(data, hdr_len)]
    return events


def _as_nobody(func):
    """Run func() as an unprivileged user in a child, return its result."""

    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rfd)
        status = 1
        try:
            os.setgroups([])
            os.setresgid(65534, 65534, 65534)
            os.setresuid(65534, 65534, 65534)
            os.write(wfd, json.dumps(func()).encode())
            status = 0
        finally:
            os._exit(status)
    os.close(wfd)
    with os.fdopen(rfd) as f:
        result = f.read()
    _, status = os.waitpid(pid, 0)
    ksft_eq(status, 0, "unprivileged request failed")
    return json.loads(result) if status == 0 else None


RTM_NEWPREFIX = 52
RTM_DELPREFIX = 53
RTM_GETPREFIX = 54
PREFIX_ADDRESS = 1
PREFIX_CACHEINFO = 2
PREFIX_ROUTER = 3
PREFIX_PROTO = 4
ND_OPT_PREFIX_INFO = 3
ND_OPT_ROUTE_INFO = 24
RTNLGRP_IPV6_ADV_PREFIX = 40
RTPROT_STATIC = 4
RTPROT_RA = 9
PREFIXMSG_LEN = 12


def _prefix_change(msg_type, ifindex, prefix, plen, router, valid=None,
                   flags=0, proto=None):
    header = struct.pack('=BBHiBBBB', socket.AF_INET6, 0, 0, ifindex,
                         ND_OPT_PREFIX_INFO, plen, 0xc0, 0)
    attrs = _nlattr(PREFIX_ADDRESS, _in6(prefix))
    attrs += _nlattr(PREFIX_ROUTER, _in6(router))
    if valid is not None:
        attrs += _nlattr(PREFIX_CACHEINFO, struct.pack('=II', valid, valid))
    if proto is not None:
        attrs += _nlattr(PREFIX_PROTO, struct.pack('=B', proto))
    err, _ = _rtnl_request(msg_type, Netlink.NLM_F_ACK | flags, header, attrs)
    return err


def _prefix_entry(hdr, attrs):
    _, _, _, ifindex, ptype, plen, _, _ = struct.unpack('=BBHiBBBB', hdr)
    _, valid = struct.unpack('=II', attrs[PREFIX_CACHEINFO])
    return {'ifindex': ifindex, 'type': ptype, 'valid': valid,
            'prefix': f"{_ntop6(attrs[PREFIX_ADDRESS])}/{plen}",
            'router': _ntop6(attrs[PREFIX_ROUTER]),
            'proto': attrs[PREFIX_PROTO][0] if PREFIX_PROTO in attrs else 0}


def _prefix_entries(ifindex=0, ptype=0, strict=False):
    """Return the advertised prefixes as dicts, or the error of the dump."""

    header = struct.pack('=BBHiBBBB', socket.AF_INET6, 0, 0, ifindex, ptype,
                         0, 0, 0)
    err, replies = _rtnl_request(RTM_GETPREFIX, Netlink.NLM_F_DUMP, header,
                                 strict=strict)
    if err == -errno.EOPNOTSUPP:
        raise KsftSkipEx("kernel does not support RTM_GETPREFIX")
    if err:
        return err
    return [_prefix_entry(hdr, attrs) for hdr, attrs in replies]


def _prefix_dump(ifindex=0):
    """Return the advertised prefixes as sorted (prefix, router) tuples."""

    entries = _prefix_entries()
    ksft_eq(type(entries), list, "RTM_GETPREFIX dump failed")
    return sorted((e['prefix'], e['router']) for e in entries
                  if not ifindex or e['ifindex'] == ifindex)


def ipv6_saddr_adv_prefix_netlink() -> None:
    """
    Source address selection prefers an address in a prefix advertised by
    the next-hop (RFC 6724 rule 5.5), with the advertised prefixes set by
    userspace with RTM_NEWPREFIX.
    """

    with NetNS() as ns:
        ip("link add name dummy1 type dummy", ns=str(ns))
        with NetNSEnter(str(ns)):
            _write_ipv6_sysctl("conf/dummy1/accept_dad", 0)
            ip("link set dev dummy1 up")
            ifindex = socket.if_nametoindex("dummy1")
            create = Netlink.NLM_F_CREATE | Netlink.NLM_F_REPLACE

            err = _prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:1::", 64,
                                 "fe80::1", flags=create)
            if err == -errno.EOPNOTSUPP:
                raise KsftSkipEx("kernel does not support RTM_NEWPREFIX")
            ksft_eq(err, 0)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:2::", 64,
                                   "fe80::2", valid=600, flags=create), 0)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:2::", 64,
                                   "fe80::4", flags=create), 0)
            ksft_eq(_prefix_dump(ifindex),
                    [("2001:db8:1::/64", "fe80::1"),
                     ("2001:db8:2::/64", "fe80::2"),
                     ("2001:db8:2::/64", "fe80::4")])

            # Like other rtnetlink objects
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:1::", 64,
                                   "fe80::1", flags=Netlink.NLM_F_CREATE),
                    -errno.EEXIST)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:3::", 64,
                                   "fe80::1", flags=Netlink.NLM_F_REPLACE),
                    -errno.ENOENT)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:3::", 64,
                                   "2001:db8::1", flags=create), -errno.EINVAL)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:3::", 64,
                                   "fe80::1", valid=0, flags=create),
                    -errno.EINVAL)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "fe80::", 64,
                                   "fe80::1", flags=create), -errno.EINVAL)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "ff02::", 16,
                                   "fe80::1", flags=create), -errno.EINVAL)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:3::", 64,
                                   "fe80::1", flags=create, proto=RTPROT_RA),
                    -errno.EINVAL)

            # Strict dump requests can ask for the entries of an interface
            ip("link add name dummy2 type dummy")
            ip("link set dev dummy2 up")
            ksft_eq(_prefix_change(RTM_NEWPREFIX,
                                   socket.if_nametoindex("dummy2"),
                                   "2001:db8:4::", 64, "fe80::1",
                                   flags=create, proto=RTPROT_STATIC), 0)
            entries = _prefix_entries(ifindex, strict=True)
            ksft_eq(sorted(e['prefix'] for e in entries),
                    ["2001:db8:1::/64", "2001:db8:2::/64", "2001:db8:2::/64"])
            ksft_eq(len(_prefix_entries(ifindex, ND_OPT_PREFIX_INFO,
                                        strict=True)), 3)
            ksft_eq(_prefix_entries(ifindex, 24, strict=True), -errno.EINVAL)
            entries = _prefix_entries(socket.if_nametoindex("dummy2"),
                                      strict=True)
            ksft_eq([(e['prefix'], e['proto'], e['valid'], e['type'])
                     for e in entries],
                    [("2001:db8:4::/64", RTPROT_STATIC, 0xffffffff,
                      ND_OPT_PREFIX_INFO)])
            # PREFIX_PROTO only removes an entry of that protocol
            ksft_eq(_prefix_change(RTM_DELPREFIX,
                                   socket.if_nametoindex("dummy2"),
                                   "2001:db8:4::", 64, "fe80::1",
                                   proto=RTPROT_RA), -errno.ENOENT)
            ip("link del dev dummy2")

            ip("-6 address add 2001:db8:1::1/64 dev dummy1")
            ip("-6 address add 2001:db8:2::1/64 dev dummy1")

            # 2001:db8:1::1 has the longest matching prefix with both
            # destinations (rule 8), but rule 5.5 comes first.
            ip("-6 route add 2001:db8:1:ff00::/56 via fe80::2 dev dummy1")
            ip("-6 route add 2001:db8:1:fe00::/56 via fe80::3 dev dummy1")

            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:2::1")
            ksft_eq(_route_get_saddr("2001:db8:1:ff00::1"), "2001:db8:2::1")
            ksft_eq(_saddr("2001:db8:1:fe00::1"), "2001:db8:1::1")
            ksft_eq(_route_get_saddr("2001:db8:1:fe00::1"), "2001:db8:1::1")

            # An address that no router advertised ties with the ones of
            # the next-hop, and has the longest matching prefix.
            ip("-6 address add 2001:db8:5::1/64 dev dummy1")
            ip("-6 route add 2001:db8:5:ff00::/56 via fe80::2 dev dummy1")
            ksft_eq(_saddr("2001:db8:5:ff00::1"), "2001:db8:5::1")
            ksft_eq(_route_get_saddr("2001:db8:5:ff00::1"), "2001:db8:5::1")
            ip("-6 address del 2001:db8:5::1/64 dev dummy1")

            _write_ipv6_sysctl("conf/dummy1/use_nexthop_prefixes", 0)
            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:1::1")
            _write_ipv6_sysctl("conf/dummy1/use_nexthop_prefixes", 1)
            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:2::1")

            # Unprivileged users can read the table, but not change it.
            dump = _as_nobody(lambda: _prefix_dump(ifindex))
            ksft_eq([tuple(e) for e in dump], _prefix_dump(ifindex))
            ksft_eq(_as_nobody(lambda: _prefix_change(
                RTM_DELPREFIX, ifindex, "2001:db8:2::", 64, "fe80::2")),
                    -errno.EPERM)

            # The lifetime does not matter to delete an entry.
            ksft_eq(_prefix_change(RTM_DELPREFIX, ifindex, "2001:db8:2::", 64,
                                   "fe80::2", valid=0), 0)
            ksft_eq(_prefix_change(RTM_DELPREFIX, ifindex, "2001:db8:2::", 64,
                                   "fe80::2"), -errno.ENOENT)
            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:1::1")

            # Entries expire.
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:2::", 64,
                                   "fe80::2", valid=2, flags=create), 0)
            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:2::1")
            ksft_busy_wait(lambda: ("2001:db8:2::/64", "fe80::2") not in
                           _prefix_dump(ifindex), sleep=0.1, deadline=10,
                           comment="entry did not expire")
            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:1::1")

            # The table is flushed when the interface goes down.
            ip("link set dev dummy1 down")
            ksft_eq(_prefix_dump(ifindex), [])


def ipv6_saddr_adv_prefix_notify() -> None:
    """
    Changes of the advertised prefixes are notified to
    RTNLGRP_IPV6_ADV_PREFIX, including expiry and flush.
    """

    with NetNS() as ns:
        ip("link add name dummy1 type dummy", ns=str(ns))
        with NetNSEnter(str(ns)):
            ip("link set dev dummy1 up")
            ifindex = socket.if_nametoindex("dummy1")
            create = Netlink.NLM_F_CREATE | Netlink.NLM_F_REPLACE
            if _prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:1::", 64,
                              "fe80::1", flags=create) == -errno.EOPNOTSUPP:
                raise KsftSkipEx("kernel does not support RTM_NEWPREFIX")

            with _rtnl_listen(RTNLGRP_IPV6_ADV_PREFIX) as sock:
                def events(count, deadline=5):
                    return [(t, _prefix_entry(h, a)['prefix'],
                             _prefix_entry(h, a)['proto'])
                            for t, h, a in _rtnl_events(sock, PREFIXMSG_LEN,
                                                        count, deadline)]

                ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:2::",
                                       64, "fe80::1", flags=create,
                                       proto=RTPROT_STATIC), 0)
                ksft_eq(_prefix_change(RTM_DELPREFIX, ifindex, "2001:db8:2::",
                                       64, "fe80::1"), 0)
                ksft_eq(events(2), [(RTM_NEWPREFIX, "2001:db8:2::/64",
                                     RTPROT_STATIC),
                                    (RTM_DELPREFIX, "2001:db8:2::/64",
                                     RTPROT_STATIC)])

                ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:3::",
                                       64, "fe80::1", valid=1,
                                       flags=create), 0)
                ksft_eq(events(2, deadline=10),
                        [(RTM_NEWPREFIX, "2001:db8:3::/64", 0),
                         (RTM_DELPREFIX, "2001:db8:3::/64", 0)])

                ip("link set dev dummy1 down")
                ksft_eq(events(1), [(RTM_DELPREFIX, "2001:db8:1::/64", 0)])


def ipv6_saddr_adv_prefix_subnet() -> None:
    """
    An advertised prefix only counts for the addresses of a subnet it
    contains, the subnet being a /64 for prefixes up to /64 and for /128.
    """

    with NetNS() as ns:
        ip("link add name dummy1 type dummy", ns=str(ns))
        with NetNSEnter(str(ns)):
            _write_ipv6_sysctl("conf/dummy1/accept_dad", 0)
            ip("link set dev dummy1 up")
            ifindex = socket.if_nametoindex("dummy1")
            create = Netlink.NLM_F_CREATE | Netlink.NLM_F_REPLACE

            # Rule 6 (matching label) prefers a.
            a = "2001:db8:1::1"
            b = "2001:db8:1::2"
            ip(f"-6 address add {a}/64 dev dummy1")
            ip(f"-6 address add {b}/64 dev dummy1")
            ip(f"addrlabel add prefix {b}/128 label 100")
            ip("-6 route add 2001:db8:9::/64 via fe80::2 dev dummy1")

            # A /128 of another router does not make one address of the
            # subnet lose.
            err = _prefix_change(RTM_NEWPREFIX, ifindex, a, 128, "fe80::3",
                                 flags=create)
            if err == -errno.EOPNOTSUPP:
                raise KsftSkipEx("kernel does not support RTM_NEWPREFIX")
            ksft_eq(err, 0)
            ksft_eq(_saddr("2001:db8:9::1"), a)

            # A /56 address is in the subnet of an advertised /64, here of
            # another router than the next-hop.
            ip("-6 address add 2001:db8:5::1/56 dev dummy1")
            ip("-6 address add 2001:db8:6::1/64 dev dummy1")
            ip("-6 route add 2001:db8:5:ff00::/56 via fe80::2 dev dummy1")
            ksft_eq(_saddr("2001:db8:5:ff00::1"), "2001:db8:5::1")
            ksft_eq(_prefix_change(RTM_NEWPREFIX, ifindex, "2001:db8:5::", 64,
                                   "fe80::3", flags=create), 0)
            ksft_eq(_saddr("2001:db8:5:ff00::1"), "2001:db8:6::1")

            # So is a /128 address.
            ip("-6 address del 2001:db8:5::1/56 dev dummy1")
            ip("-6 address add 2001:db8:5::2/128 dev dummy1")
            ksft_eq(_saddr("2001:db8:5:ff00::1"), "2001:db8:6::1")


def _ra_sock_from(ns_r, ifname, router):
    """Raw ICMPv6 socket sending from the link-local address router."""

    sock, ifindex = _ra_router_sock(ns_r, ifname)
    sock.bind((router, 0, 0, ifindex))
    return sock, ifindex


def _wait_addr(prefix, deadline=10):
    """Return the address in prefix/64, waiting for SLAAC."""

    end = time.time() + deadline
    while time.time() < end:
        for entry in ip("-6 address show", json=True):
            for addr in entry.get('addr_info', []):
                if _in6(addr['local'])[:8] == _in6(prefix)[:8]:
                    return addr['local']
        time.sleep(0.1)
    return None


def ipv6_saddr_adv_prefix_ra() -> None:
    """
    The kernel remembers which router advertised which prefix in Prefix
    Information options, and source address selection prefers an address in
    a prefix advertised by the next-hop (RFC 6724 rule 5.5).
    """

    with NetNS() as ns_h, NetNS() as ns_r:
        ip(f"link add veth0 netns {ns_h} type veth peer name veth1 netns {ns_r}")
        with NetNSEnter(str(ns_h)):
            _write_ipv6_sysctl("conf/veth0/accept_dad", 0)
            _write_ipv6_sysctl("conf/veth0/accept_ra", 2)
            _write_ipv6_sysctl("conf/veth0/forwarding", 0)
        ip("link set dev veth0 up", ns=str(ns_h))
        ip("link set dev veth1 up", ns=str(ns_r))
        # Two routers on the same link.
        ip("-6 address add fe80::1/64 dev veth1 nodad", ns=str(ns_r))
        ip("-6 address add fe80::2/64 dev veth1 nodad", ns=str(ns_r))

        sock1, ifindex = _ra_sock_from(ns_r, "veth1", "fe80::1")
        sock2, _ = _ra_sock_from(ns_r, "veth1", "fe80::2")

        # A and L flags set, router lifetime 0, i.e. not default routers.
        _send_ra(sock1, ifindex, 0, pio=('2001:db8:1::', 64, 600),
                 pio_flags=0xc0)
        _send_ra(sock2, ifindex, 0, pio=('2001:db8:2::', 64, 600),
                 pio_flags=0xc0)

        with NetNSEnter(str(ns_h)):
            a1 = _wait_addr('2001:db8:1::')
            a2 = _wait_addr('2001:db8:2::')
            ksft_not_none(a1, "no address from the PIO of fe80::1")
            ksft_not_none(a2, "no address from the PIO of fe80::2")
            if a1 is None or a2 is None:
                return

            veth0 = socket.if_nametoindex("veth0")
            ksft_eq(_prefix_dump(veth0), [("2001:db8:1::/64", "fe80::1"),
                                          ("2001:db8:2::/64", "fe80::2")])
            ksft_eq({e['proto'] for e in _prefix_entries(veth0)}, {RTPROT_RA})

            ip("-6 route add 2001:db8:1:ff00::/56 via fe80::2 dev veth0")
            ksft_eq(_saddr("2001:db8:1:ff00::1"), a2)

            # The second router also advertises the first prefix.
            _send_ra(sock2, ifindex, 0, pio=('2001:db8:1::', 64, 600),
                     pio_flags=0xc0)
            ksft_busy_wait(lambda: ("2001:db8:1::/64", "fe80::2") in _prefix_dump(),
                           deadline=5, comment="fe80::2 did not advertise 2001:db8:1::/64")
            ksft_eq(_saddr("2001:db8:1:ff00::1"), a1)

            # A zero valid lifetime withdraws the prefix of that router, even
            # though the address itself stays (RFC 4862 section 5.5.3 e).
            _send_ra(sock2, ifindex, 0, pio=('2001:db8:1::', 64, 0),
                     pio_flags=0xc0)
            ksft_busy_wait(lambda: ("2001:db8:1::/64", "fe80::2") not in _prefix_dump(),
                           deadline=5, comment="2001:db8:1::/64 of fe80::2 not withdrawn")
            ksft_eq(_saddr("2001:db8:1:ff00::1"), a2)

            # Router Advertisements leave the entries of userspace alone.
            ksft_eq(_prefix_change(RTM_NEWPREFIX, veth0, "2001:db8:1::", 64,
                                   "fe80::2",
                                   flags=Netlink.NLM_F_CREATE |
                                   Netlink.NLM_F_REPLACE,
                                   proto=RTPROT_STATIC), 0)
            _send_ra(sock2, ifindex, 0, pio=('2001:db8:1::', 64, 0),
                     pio_flags=0xc0)
            # Wait for the RA through an entry it does change.
            _send_ra(sock2, ifindex, 0, pio=('2001:db8:2::', 64, 0),
                     pio_flags=0xc0)
            ksft_busy_wait(lambda: ("2001:db8:2::/64", "fe80::2") not in _prefix_dump(),
                           deadline=5, comment="2001:db8:2::/64 of fe80::2 not withdrawn")
            ksft_in(("2001:db8:1::/64", "fe80::2"), _prefix_dump(veth0))


def ipv6_saddr_adv_prefix_icmp() -> None:
    """
    ICMPv6 errors about forwarded packets prefer a source address in a
    prefix advertised by the next-hop (RFC 6724 rule 5.5).
    """

    with NetNS() as ns_a, NetNS() as ns_n:
        ip(f"link add a0 netns {ns_a} type veth peer name n0 netns {ns_n}")
        with NetNSEnter(str(ns_n)):
            _write_ipv6_sysctl("conf/all/forwarding", 1)
            _write_ipv6_sysctl("conf/n0/accept_dad", 0)
            _write_ipv6_sysctl("icmp/ratelimit", 0)
            ip("link add name dummy1 type dummy")
            ip("link set dev dummy1 up")
            ip("link set dev n0 up")
            ip("-6 address add fe80::1/64 dev n0 nodad")
            ip("-6 address add 2001:db8:1::1/64 dev n0 nodad")
            ip("-6 address add 2001:db8:2::1/64 dev n0 nodad")
            ip("-6 route add 2001:db8:5::/64 dev dummy1")
            # 2001:db8:1::1 has the longest matching prefix (rule 8), but
            # another router advertised it.
            ip("-6 route add 2001:db8:1:ff00::/56 via fe80::a dev n0")
            err = _prefix_change(RTM_NEWPREFIX, socket.if_nametoindex("n0"),
                                 "2001:db8:2::", 64, "fe80::a",
                                 flags=Netlink.NLM_F_CREATE)
            if err == -errno.EOPNOTSUPP:
                raise KsftSkipEx("kernel does not support RTM_NEWPREFIX")
            ksft_eq(err, 0)
            ksft_eq(_prefix_change(RTM_NEWPREFIX, socket.if_nametoindex("n0"),
                                   "2001:db8:1::", 64, "fe80::b",
                                   flags=Netlink.NLM_F_CREATE), 0)

        with NetNSEnter(str(ns_a)):
            _write_ipv6_sysctl("conf/a0/accept_dad", 0)
            ip("link set dev a0 up")
            ip("-6 address add fe80::a/64 dev a0 nodad")
            ip("-6 address add 2001:db8:1:ff00::a/128 dev a0 nodad")
            ip("-6 route add 2001:db8:5::/64 via fe80::1 dev a0")

            def time_exceeded_from():
                with socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                   socket.IPPROTO_ICMPV6) as icmp, \
                     socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
                    icmp.settimeout(5)
                    udp.bind(("2001:db8:1:ff00::a", 0))
                    udp.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_UNICAST_HOPS, 1)
                    udp.sendto(b"x", ("2001:db8:5::1", 9))
                    while True:
                        data, addr = icmp.recvfrom(1500)
                        if data[0] == 3:	# Time Exceeded
                            return addr[0]

            ksft_eq(time_exceeded_from(), "2001:db8:2::1")
            with NetNSEnter(str(ns_n)):
                _write_ipv6_sysctl("conf/n0/use_nexthop_prefixes", 0)
            ksft_eq(time_exceeded_from(), "2001:db8:1::1")


RTM_NEWRULE = 32
FRA_SRC = 2
FRA_PRIORITY = 6
FRA_TABLE = 15
FR_ACT_TO_TBL = 1
FIB_RULE_FIND_SADDR = 0x00010000


def ipv6_saddr_adv_prefix_rule() -> None:
    """
    A rule that matches the source address selects it with RFC 6724 rule
    5.5, like the source address of the route the rule leads to.
    """

    with NetNS() as ns:
        ip("link add name dummy1 type dummy", ns=str(ns))
        with NetNSEnter(str(ns)):
            _write_ipv6_sysctl("conf/dummy1/accept_dad", 0)
            ip("link set dev dummy1 up")
            ip("-6 address add 2001:db8:1::1/64 dev dummy1")
            ip("-6 address add 2001:db8:2::1/64 dev dummy1")
            err = _prefix_change(RTM_NEWPREFIX, socket.if_nametoindex("dummy1"),
                                 "2001:db8:2::", 64, "fe80::2",
                                 flags=Netlink.NLM_F_CREATE)
            if err == -errno.EOPNOTSUPP:
                raise KsftSkipEx("kernel does not support RTM_NEWPREFIX")
            ksft_eq(err, 0)
            ksft_eq(_prefix_change(RTM_NEWPREFIX,
                                   socket.if_nametoindex("dummy1"),
                                   "2001:db8:1::", 64, "fe80::3",
                                   flags=Netlink.NLM_F_CREATE), 0)

            ip("-6 route add 2001:db8:1:ff00::/56 via fe80::2 dev dummy1 table 100")
            ip("-6 route add 2001:db8:1:ff00::/56 via fe80::3 dev dummy1")

            # "from 2001:db8:2::/64 lookup 100", matched against the source
            # address selected for the route of table 100.
            header = struct.pack('=BBBBBBBBI', socket.AF_INET6, 0, 64, 0, 0,
                                 0, 0, FR_ACT_TO_TBL, FIB_RULE_FIND_SADDR)
            attrs = _nlattr(FRA_SRC, _in6("2001:db8:2::"))
            attrs += _nlattr(FRA_TABLE, struct.pack('=I', 100))
            attrs += _nlattr(FRA_PRIORITY, struct.pack('=I', 100))
            err, _ = _rtnl_request(RTM_NEWRULE, Netlink.NLM_F_ACK |
                                   Netlink.NLM_F_CREATE, header, attrs)
            ksft_eq(err, 0)

            ksft_eq(_saddr("2001:db8:1:ff00::1"), "2001:db8:2::1")
            route = ip("-6 route get 2001:db8:1:ff00::1", json=True)[0]
            ksft_eq((route.get('gateway'), route.get('prefsrc')),
                    ("fe80::2", "2001:db8:2::1"))


RTM_NEWNDUSEROPT = 68
RTNLGRP_ND_USEROPT = 20
NDUSEROPT_SRCADDR = 1
NDUSEROPT_RA_FLAGS = 2
NDUSEROPTMSG_LEN = 16


def _useropts(sock, count, deadline=5):
    """
    Return the next count RTM_NEWNDUSEROPT received on sock, as
    (option type, {attr type: payload}), or fewer on timeout.
    """

    opts = []
    end = time.time() + deadline
    while len(opts) < count and time.time() < end:
        sock.settimeout(max(end - time.time(), 0.01))
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        for nl_type, raw, hdr, _ in _nlmsgs(data, NDUSEROPTMSG_LEN):
            if nl_type != RTM_NEWNDUSEROPT:
                continue
            _, _, opts_len = struct.unpack_from('=BBH', hdr)
            # The attributes follow the option, a multiple of 8 bytes long.
            _, _, _, attrs = next(_nlmsgs(raw, NDUSEROPTMSG_LEN + opts_len))
            opts.append((raw[16 + NDUSEROPTMSG_LEN], attrs))
    return opts


def ipv6_ndisc_useropt_ra_flags() -> None:
    """
    The options of Router Advertisements forwarded to userspace come with
    the flags of the RA, e.g. the SNAC Router flag (RFC 6724 rules 1 and 5
    of draft-ietf-6man-rfc6724-update).
    """

    with NetNS() as ns_h, NetNS() as ns_r:
        ip(f"link add veth0 netns {ns_h} type veth peer name veth1 netns {ns_r}")
        with NetNSEnter(str(ns_h)):
            _write_ipv6_sysctl("conf/veth0/accept_dad", 0)
            _write_ipv6_sysctl("conf/veth0/accept_ra", 2)
        ip("link set dev veth0 up", ns=str(ns_h))
        ip("link set dev veth1 up", ns=str(ns_r))
        ip("-6 address add fe80::1/64 dev veth1 nodad", ns=str(ns_r))
        sock, ifindex = _ra_sock_from(ns_r, "veth1", "fe80::1")

        with NetNSEnter(str(ns_h)):
            listener = _rtnl_listen(RTNLGRP_ND_USEROPT)
            defer(listener.close)

        for ra_flags in (0x42, 0x00):
            _send_ra(sock, ifindex, 0, pio=('fd00:1::', 64, 600),
                     pio_flags=0x80, ra_flags=ra_flags)
            opts = _useropts(listener, 1)
            ksft_eq(len(opts), 1)
            if not opts:
                return
            opt_type, attrs = opts[0]
            ksft_eq(opt_type, ND_OPT_PREFIX_INFO)
            ksft_eq(attrs.get(NDUSEROPT_SRCADDR), _in6("fe80::1"))
            if NDUSEROPT_RA_FLAGS not in attrs:
                raise KsftSkipEx("kernel does not report the RA flags")
            ksft_eq(attrs[NDUSEROPT_RA_FLAGS], bytes([ra_flags]))


def ipv6_ndisc_useropt_rio() -> None:
    """
    Route Information options are forwarded to userspace, like Prefix
    Information options, for the known-local ULAs of
    draft-ietf-6man-rfc6724-update, even when the kernel does not install
    them as routes.
    """

    with NetNS() as ns_h, NetNS() as ns_r:
        ip(f"link add veth0 netns {ns_h} type veth peer name veth1 netns {ns_r}")
        with NetNSEnter(str(ns_h)):
            _write_ipv6_sysctl("conf/veth0/accept_dad", 0)
            _write_ipv6_sysctl("conf/veth0/accept_ra", 2)
            _write_ipv6_sysctl("conf/veth0/accept_ra_rt_info_max_plen", 0)
        ip("link set dev veth0 up", ns=str(ns_h))
        ip("link set dev veth1 up", ns=str(ns_r))
        ip("-6 address add fe80::1/64 dev veth1 nodad", ns=str(ns_r))
        sock, ifindex = _ra_sock_from(ns_r, "veth1", "fe80::1")

        with NetNSEnter(str(ns_h)):
            listener = _rtnl_listen(RTNLGRP_ND_USEROPT)
            defer(listener.close)

        _send_ra(sock, ifindex, 0, rio=('fd00:2::', 48, 600),
                 pio=('fd00:1::', 64, 600), pio_flags=0x80)
        opts = _useropts(listener, 2)
        ksft_ge(len(opts), 1)
        if len(opts) == 1:
            raise KsftSkipEx("kernel does not forward RIOs")
        ksft_eq(sorted(t for t, _ in opts), [ND_OPT_PREFIX_INFO, ND_OPT_ROUTE_INFO])
        for _, attrs in opts:
            ksft_eq(attrs.get(NDUSEROPT_SRCADDR), _in6("fe80::1"))


RTM_NEWADDRLABEL = 72
RTM_DELADDRLABEL = 73
RTM_GETADDRLABEL = 74
IFAL_ADDRESS = 1
IFAL_LABEL = 2
IFAL_PRECEDENCE = 3
IFAL_PROTOCOL = 4
RTNLGRP_IPV6_ADDRLABEL = 41
RTPROT_KERNEL = 2
IFADDRLBLMSG_LEN = 12


def _addrlabel_change(msg_type, prefix, plen, label, precedence=None, flags=0,
                      ifindex=0, proto=None):
    header = struct.pack('=BBBBII', socket.AF_INET6, 0, plen, 0, ifindex, 0)
    attrs = _nlattr(IFAL_ADDRESS, _in6(prefix))
    attrs += _nlattr(IFAL_LABEL, struct.pack('=I', label))
    if precedence is not None:
        attrs += _nlattr(IFAL_PRECEDENCE, struct.pack('=I', precedence))
    if proto is not None:
        attrs += _nlattr(IFAL_PROTOCOL, struct.pack('=B', proto))
    err, _ = _rtnl_request(msg_type, Netlink.NLM_F_ACK | flags, header, attrs)
    return err


def _addrlabel_entry(hdr, attrs):
    _, _, plen, _, ifindex, _ = struct.unpack('=BBBBII', hdr)
    entry = {'prefix': f"{_ntop6(attrs[IFAL_ADDRESS])}/{plen}",
             'label': struct.unpack('=I', attrs[IFAL_LABEL])[0],
             'ifindex': ifindex}
    if IFAL_PRECEDENCE in attrs:
        entry['precedence'] = struct.unpack('=I', attrs[IFAL_PRECEDENCE])[0]
    if IFAL_PROTOCOL in attrs:
        entry['proto'] = attrs[IFAL_PROTOCOL][0]
    return entry


def _addrlabel_dump(ifindex=0):
    """Return the address label entries of ifindex as {prefix: entry}."""

    header = struct.pack('=BBBBII', socket.AF_INET6, 0, 0, 0, 0, 0)
    err, replies = _rtnl_request(RTM_GETADDRLABEL, Netlink.NLM_F_DUMP, header)
    ksft_eq(err, 0, "RTM_GETADDRLABEL dump failed")
    table = {}
    for hdr, attrs in replies:
        entry = _addrlabel_entry(hdr, attrs)
        if entry['ifindex'] == ifindex:
            table[entry.pop('prefix')] = entry
    return table


def ipv6_addrlabel_precedence() -> None:
    """
    IFAL_PRECEDENCE carries the RFC 6724 precedence of an address selection
    policy entry. Privileged users set it, everybody can read it.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            table = _addrlabel_dump()
            if 'precedence' not in table.get('::/0', {}):
                raise KsftSkipEx("kernel does not support IFAL_PRECEDENCE")

            # The default table, updated by draft-ietf-6man-rfc6724-update.
            ksft_eq(table['::1/128']['precedence'], 50)
            ksft_eq(table['::/0']['precedence'], 40)
            ksft_eq(table['fc00::/7']['precedence'], 30)
            ksft_eq(table['::ffff:0.0.0.0/96']['precedence'], 20)
            ksft_eq(table['2002::/16']['precedence'], 5)
            ksft_not_in('precedence', table['2001:10::/28'])

            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:1::', 48, 14, 45), 0)
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:2::', 48, 15), 0)
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:3::', 48, 16,
                                      0xffffffff), -errno.ERANGE)

            table = _addrlabel_dump()
            ksft_eq(table['fd00:1::/48'], {'label': 14, 'precedence': 45,
                                           'ifindex': 0})
            ksft_not_in('precedence', table['fd00:2::/48'])
            ksft_not_in('fd00:3::/48', table)

            # Replacing an entry without the attribute drops the precedence.
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:1::', 48, 14,
                                      flags=Netlink.NLM_F_REPLACE), 0)
            ksft_not_in('precedence', _addrlabel_dump()['fd00:1::/48'])
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:1::', 48, 14, 45,
                                      flags=Netlink.NLM_F_REPLACE), 0)

            # Unless the prefix is in the default table, like with
            # "ip addrlabel del" and "add" to change the label of ::/0.
            ksft_eq(_addrlabel_change(RTM_DELADDRLABEL, '::', 0, 1), 0)
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, '::', 0, 7), 0)
            ksft_eq(_addrlabel_dump()['::/0'], {'label': 7, 'precedence': 40,
                                                'ifindex': 0})
            # But not for the entry of an interface.
            lo = socket.if_nametoindex("lo")
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, '::', 0, 8,
                                      ifindex=lo), 0)
            ksft_not_in('precedence', _addrlabel_dump(lo)['::/0'])

            table = _as_nobody(_addrlabel_dump)
            ksft_in('fd00:1::/48', table)
            ksft_eq(table['fd00:1::/48'].get('precedence'), 45)
            ksft_eq(_as_nobody(lambda: _addrlabel_change(
                RTM_NEWADDRLABEL, 'fd00:4::', 48, 14, 45)), -errno.EPERM)

            ksft_eq(_addrlabel_change(RTM_DELADDRLABEL, 'fd00:1::', 48, 14), 0)
            ksft_not_in('fd00:1::/48', _addrlabel_dump())


def ipv6_addrlabel_notify() -> None:
    """
    Changes of the address selection policy table are notified, and
    IFAL_PROTOCOL tells who added an entry.
    """

    with NetNS() as ns:
        with NetNSEnter(str(ns)):
            if _addrlabel_dump()['::/0'].get('proto') != RTPROT_KERNEL:
                raise KsftSkipEx("kernel does not support IFAL_PROTOCOL")

            sock = _rtnl_listen(RTNLGRP_IPV6_ADDRLABEL)
            defer(sock.close)

            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:1::', 48, 14, 45,
                                      proto=RTPROT_STATIC), 0)
            ksft_eq(_addrlabel_change(RTM_NEWADDRLABEL, 'fd00:1::', 48, 15, 45,
                                      flags=Netlink.NLM_F_REPLACE,
                                      proto=RTPROT_STATIC), 0)
            # Only remove an entry of the given protocol.
            ksft_eq(_addrlabel_change(RTM_DELADDRLABEL, 'fd00:1::', 48, 15,
                                      proto=RTPROT_RA), -errno.ESRCH)
            ksft_eq(_addrlabel_change(RTM_DELADDRLABEL, 'fd00:1::', 48, 15,
                                      proto=RTPROT_STATIC), 0)
            ksft_eq(_addrlabel_change(RTM_DELADDRLABEL, 'fd00:1::', 48, 15),
                    -errno.ESRCH)

            events = [(t, _addrlabel_entry(h, a))
                      for t, h, a in _rtnl_events(sock, IFADDRLBLMSG_LEN, 4,
                                                  deadline=2)]
            entry = {'prefix': 'fd00:1::/48', 'precedence': 45, 'ifindex': 0,
                     'proto': RTPROT_STATIC}
            ksft_eq(events, [(RTM_NEWADDRLABEL, {**entry, 'label': 14}),
                             (RTM_NEWADDRLABEL, {**entry, 'label': 15}),
                             (RTM_DELADDRLABEL, {**entry, 'label': 15})])

            # The sequence number of the table changes with every change.
            seqs = set()
            for msg_type in (RTM_NEWADDRLABEL, RTM_DELADDRLABEL):
                ksft_eq(_addrlabel_change(msg_type, 'fd00:2::', 48, 16), 0)
                header = struct.pack('=BBBBII', socket.AF_INET6, 0, 0, 0, 0, 0)
                _, replies = _rtnl_request(RTM_GETADDRLABEL,
                                           Netlink.NLM_F_DUMP, header)
                seqs.add(struct.unpack('=BBBBII', replies[0][0])[5])
            ksft_eq(len(seqs), 2)


def main() -> None:
    ksft_run([dump_mcaddr_check, dump_mcaddr6_check, ipv4_devconf_notify,
              ipv6_route_del_reason_expired,
              ipv6_route_del_reason_ra_withdrawn,
              ipv6_route_del_reason_absent,
              ipv6_saddr_adv_prefix_netlink,
              ipv6_saddr_adv_prefix_notify,
              ipv6_saddr_adv_prefix_subnet,
              ipv6_saddr_adv_prefix_ra,
              ipv6_saddr_adv_prefix_icmp,
              ipv6_saddr_adv_prefix_rule,
              ipv6_ndisc_useropt_ra_flags,
              ipv6_ndisc_useropt_rio,
              ipv6_addrlabel_precedence,
              ipv6_addrlabel_notify])
    ksft_exit()

if __name__ == "__main__":
    main()
