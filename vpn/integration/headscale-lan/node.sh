#!/bin/sh
# Lab entrypoint for one tailscaled container.
# LAN_DROP_CIDR / LAN_FORWARD / LAN_ECHO are harness switches, not Tailscale
# product settings. See docs/15-VPN-LAN-AND-GATEWAY.md.
set -eu

if [ -n "${LAN_DROP_CIDR:-}" ]; then
	iptables -I OUTPUT -d "$LAN_DROP_CIDR" -j DROP
	iptables -I INPUT -s "$LAN_DROP_CIDR" -j DROP
fi

# OrbStack routes between user-defined bridges on the host. Without this, a
# member reaches the lab prefix via the docker gateway and the "before
# approval" / "without --accept-routes" checks are meaningless. Tailscale
# subnet traffic leaves through tailscale0 and is kept.
if [ -n "${LAN_SINK_EXCEPT_TUN:-}" ]; then
	iptables -I OUTPUT -d "$LAN_SINK_EXCEPT_TUN" ! -o tailscale0 -j DROP
fi

# Keep the underlay on IPv4 so a direct path cannot sneak through IPv6.
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true

if [ "${LAN_FORWARD:-}" = "1" ]; then
	# OrbStack marks some net.ipv4 keys read-only. A failing sysctl must not
	# kill the entrypoint (set -e); the test asserts ip_forward afterwards.
	sysctl -w net.ipv4.ip_forward=1 || echo "lan-node: ip_forward sysctl failed" >&2
	sysctl -w net.ipv4.conf.all.rp_filter=0 || echo "lan-node: rp_filter all unchanged" >&2
	sysctl -w net.ipv4.conf.default.rp_filter=0 || echo "lan-node: rp_filter default unchanged" >&2
fi

if [ "${LAN_ECHO:-}" = "1" ]; then
	# Allowed port 8740 and denied port 8080. Both stay up so an ACL drop is
	# distinguishable from "nothing is listening".
	(while true; do nc -lk -p 8740 -e echo ok; done) >/dev/null 2>&1 &
	(while true; do nc -lk -p 8080 -e echo ok; done) >/dev/null 2>&1 &
fi

tun_flag=""
if [ ! -c /dev/net/tun ]; then
	echo "lan-node: /dev/net/tun missing; falling back to userspace-networking" >&2
	tun_flag="--tun=userspace-networking"
fi

# shellcheck disable=SC2086
tailscaled \
	--state=/var/lib/tailscale/tailscaled.state \
	--socket=/var/run/tailscale/tailscaled.sock \
	--port=41641 \
	$tun_flag &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; exit 0' INT TERM
wait "$pid"
