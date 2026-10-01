#!/bin/sh
set -eu

BRIDGE_IF="bridge100"
BIND_IP="192.168.2.1"
ANCHOR="com.apple/portal_ua_probe"
PYTHON="/opt/homebrew/bin/python3"
SCRIPT="/Users/kahnmndez/Documents/Portal/scripts/captive_portal_compat_probe.py"

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "Run this helper with sudo so it can bind port 80 and manage its PF anchor." >&2
    exit 1
fi

if ! /sbin/ifconfig "$BRIDGE_IF" | /usr/bin/grep -q "inet $BIND_IP "; then
    echo "$BIND_IP is not assigned to $BRIDGE_IF; refusing to change PF." >&2
    exit 1
fi

if /usr/sbin/lsof -nP -iTCP:80 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "TCP port 80 already has a listener; stop it before running this helper." >&2
    exit 1
fi

if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q 'Status: Enabled'; then
    echo "PF is not enabled; refusing to enable or modify the global firewall." >&2
    exit 1
fi

FILTER_RULES="$(/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null)"
NAT_RULES="$(/sbin/pfctl -a "$ANCHOR" -sn 2>/dev/null)"
EXPECTED_NAT_RULE="rdr pass on bridge100 inet proto tcp from 192.168.2.0/24 to any port 80 -> 192.168.2.1 port 80"
NORMALIZED_NAT_RULES="$(printf '%s\n' "$NAT_RULES" | /usr/bin/sed -E \
    -e 's/port = 80/port 80/g' \
    -e 's/port = http/port 80/g' \
    -e 's/port http/port 80/g')"

if [ -n "$FILTER_RULES" ]; then
    echo "PF anchor $ANCHOR contains filter rules; refusing to change or clear them." >&2
    exit 1
fi

ANCHOR_CREATED=0
cleanup() {
    if [ "$ANCHOR_CREATED" -eq 1 ]; then
        /sbin/pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

if [ -z "$NAT_RULES" ]; then
    /sbin/pfctl -a "$ANCHOR" -f - <<'PF'
rdr pass on bridge100 inet proto tcp from 192.168.2.0/24 to any port 80 -> 192.168.2.1 port 80
PF
    ANCHOR_CREATED=1
elif [ "$NORMALIZED_NAT_RULES" = "$EXPECTED_NAT_RULE" ]; then
    echo "Reusing the existing exact HTTP redirect in $ANCHOR; it will be left in place on exit."
else
    echo "PF anchor $ANCHOR contains a different or additional NAT rule; refusing to replace or clear it." >&2
    exit 1
fi

echo "Dedicated Portal redirect is active. The HTTP process drops to the invoking user after binding."
echo "Ctrl-C stops the probe; a rule added by this run is cleared, while an existing matching rule is left in place."
"$PYTHON" "$SCRIPT" --bind "$BIND_IP"
