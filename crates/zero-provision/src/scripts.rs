//! The shell the installer runs on the server.
//!
//! Each piece does one job and is run on its own by `Connection::script`, which
//! sends it on standard input to `sh -s` with `set -eu` already on. Values come
//! in as environment variables that were checked against a tiny alphabet, so
//! nothing here is ever built by pasting user text into a command. A piece that
//! cannot go on exits with a number the installer turns into a sentence.

/// Make sure the downloader and the certificate store exist. Exit 40 when they
/// are missing and nothing can install them.
pub const TOOLS: &str = r#"
need=""
command -v curl >/dev/null 2>&1 || need="$need curl"
command -v tar >/dev/null 2>&1 || need="$need tar"
[ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || need="$need ca-certificates"
[ -n "$need" ] || exit 0
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >&2
  apt-get install -y -qq $need >&2
elif command -v dnf >/dev/null 2>&1; then dnf install -y -q $need >&2
elif command -v yum >/dev/null 2>&1; then yum install -y -q $need >&2
else echo "no package manager to install:$need" >&2; exit 40; fi
"#;

/// Find the release to install and fetch its signed checksum list. `TAG` is a
/// tag or `latest`. Prints `tag=`, `sums=` (base64) and `sig=`. Exit 20-22:
/// no release, no list, no signature.
pub const MANIFEST: &str = r#"
tag="$TAG"
if [ "$tag" = "latest" ]; then
  tag=$(curl -fsSL --max-time 25 "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
fi
[ -n "$tag" ] || { echo "no release found" >&2; exit 20; }
base="https://github.com/$REPO/releases/download/$tag"
install -d -m 700 "$WORK"
curl -fsSL --max-time 40 -o "$WORK/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || { echo "the release has no checksum list" >&2; exit 21; }
curl -fsSL --max-time 40 -o "$WORK/SHA256SUMS.txt.sig" "$base/SHA256SUMS.txt.sig" || { echo "the release has no signature" >&2; exit 22; }
echo "tag=$tag"
echo "sums=$(base64 -w0 "$WORK/SHA256SUMS.txt")"
echo "sig=$(tr -d '\n' < "$WORK/SHA256SUMS.txt.sig")"
"#;

/// Download one release file and keep it only if its hash is `SHA`. Exit 30 on
/// a mismatch, after deleting the file.
pub const FETCH: &str = r#"
install -d -m 700 "$WORK"
curl -fL --max-time 900 -o "$WORK/program" "https://github.com/$REPO/releases/download/$TAG/$ASSET"
got=$(sha256sum "$WORK/program" | cut -d' ' -f1)
if [ "$got" != "$SHA" ]; then rm -f "$WORK/program"; echo "checksum mismatch" >&2; exit 30; fi
chmod 755 "$WORK/program"
"#;

/// Create the account and directories the server uses.
pub const USER_AND_DIRS: &str = r#"
getent group "$SVC_USER" >/dev/null 2>&1 || groupadd --system "$SVC_USER"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --gid "$SVC_USER" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 755 "$PROGRAM_DIR"
install -d -m 750 -o root -g "$SVC_USER" "$ETC_DIR"
"#;

/// Put the downloaded or uploaded program in place, replacing any older one
/// atomically (a running server keeps its old copy open until restarted).
pub const PLACE_PROGRAM: &str = r#"
install -m 755 -o root -g root "$WORK/program" "$PROGRAM.new"
mv -f "$PROGRAM.new" "$PROGRAM"
"#;

/// Reload systemd, start the service and wait until it stays up.
pub const START: &str = r#"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
i=0
while [ $i -lt 12 ]; do
  if systemctl is-active --quiet "$SERVICE"; then break; fi
  i=$((i+1)); sleep 1
done
if ! systemctl is-active --quiet "$SERVICE"; then
  journalctl -u "$SERVICE" -n 25 --no-pager >&2 || true
  exit 50
fi
sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
  journalctl -u "$SERVICE" -n 25 --no-pager >&2 || true
  exit 51
fi
"#;

/// Wait for a TCP port to be listening; `PORT` and `PROTO` (`tcp` or `udp`).
/// Exit 52 if it never does.
pub const WAIT_PORT: &str = r#"
i=0
flag=ltn; [ "$PROTO" = udp ] && flag=lun
while [ $i -lt 15 ]; do
  if ss -H -$flag "sport = :$PORT" 2>/dev/null | grep -q .; then exit 0; fi
  i=$((i+1)); sleep 1
done
echo "nothing is listening on $PROTO/$PORT" >&2
exit 52
"#;

/// Open ports in the firewall the server already has, if it has one that is
/// switched on; never turns a firewall on. `TCP` and `UDP` are comma lists
/// (possibly `none`). Prints which firewall it changed, or `none`.
pub const FIREWALL: &str = r#"
tcp=$(echo "$TCP" | tr ',' ' '); udp=$(echo "$UDP" | tr ',' ' ')
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  for p in $tcp; do [ "$p" = none ] || ufw allow "$p/tcp" >/dev/null; done
  for p in $udp; do [ "$p" = none ] || ufw allow "$p/udp" >/dev/null; done
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  for p in $tcp; do [ "$p" = none ] || firewall-cmd --permanent --add-port="$p/tcp" >/dev/null; done
  for p in $udp; do [ "$p" = none ] || firewall-cmd --permanent --add-port="$p/udp" >/dev/null; done
  firewall-cmd --reload >/dev/null
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
"#;

/// Let the app's key log in as `LOGIN_USER`. The public key line is in
/// `$WORK/app.pub`. Idempotent.
pub const ADD_KEY: &str = r#"
home=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
[ -n "$home" ] || exit 60
install -d -m 700 -o "$LOGIN_USER" "$home/.ssh"
touch "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
chown "$LOGIN_USER" "$home/.ssh/authorized_keys"
ak="$home/.ssh/authorized_keys"
if ! grep -qxF -f "$WORK/app.pub" "$ak"; then
  # A last line without a newline would swallow the new key (and break it).
  [ -z "$(tail -c1 "$ak")" ] || echo >> "$ak"
  cat "$WORK/app.pub" >> "$ak"
  [ -z "$(tail -c1 "$ak")" ] || echo >> "$ak"
fi
"#;

/// Generate this server's WireGuard key pair with the installed server
/// program and store it in `$TUNNEL_CONF` (mode 640, `root:$SVC_USER`).
/// Only the public half is printed; the private half never leaves the
/// server. Prints `public_key=`. Exit 60 when the tool fails.
pub const WG_KEYGEN: &str = r#"
out=$("$BIN" wg 2>/dev/null || "$BIN" tools wg 2>/dev/null) || { echo "the key tool failed" >&2; exit 60; }
priv=$(printf '%s\n' "$out" | sed -n 's/^PrivateKey: //p')
pub=$(printf '%s\n' "$out" | sed -n 's/^Password (PublicKey): //p')
[ -n "$priv" ] && [ -n "$pub" ] || { echo "the key tool printed no keys" >&2; exit 60; }
printf 'private_key=%s\npublic_key=%s\n' "$priv" "$pub" > "$TUNNEL_CONF.new"
chmod 640 "$TUNNEL_CONF.new"
chown "root:$SVC_USER" "$TUNNEL_CONF.new"
mv -f "$TUNNEL_CONF.new" "$TUNNEL_CONF"
echo "public_key=$pub"
"#;

/// Read this server's tunnel public key back (for re-linking without key
/// rotation). Prints `public_key=`. Exit 61 when there is none.
pub const TUNNEL_PUBKEY: &str = r#"
pub=$(sed -n 's/^public_key=//p' "$TUNNEL_CONF" 2>/dev/null)
[ -n "$pub" ] || { echo "no tunnel key on this server" >&2; exit 61; }
echo "public_key=$pub"
"#;

/// Merge the tunnel fragment into the server config and restart the service.
///
/// `$FRAGMENT_FILE` holds the fragment JSON. Three kinds:
/// - `{"kind": "outbound"|"inbound", "object": {...}}`: the object's settings
///   may contain `@TUNNEL_PRIVATE_KEY@` (replaced with the private key from
///   `$TUNNEL_CONF`) and `@REALITY_PRIVATE_KEY@` (from `$TUNNEL_RT_CONF`);
///   each key is only required when its placeholder is actually present. The
///   object replaces the entry with the same tag in the config, or is
///   appended.
/// - `{"kind": "routetag", "tag": <outbound tag>}`: retargets the gateway's
///   client-inbounds catch-all routing rule (the one with `inboundTag` and
///   no domain/ip selectors) at the named outbound, which must exist.
///
/// Then the config is checked and the service restarted. Exit 61 without
/// python3 or when a required key is missing, 62 on a rejected config,
/// 63 when the service does not stay up, 64 on a bad routetag fragment.
pub const TUNNEL_UP: &str = r#"
command -v python3 >/dev/null 2>&1 || { echo "python3 is missing on the server" >&2; exit 61; }
python3 - "$SERVER_CONFIG" "$TUNNEL_CONF" "$TUNNEL_RT_CONF" "$TUNNEL_C_CONF" "$FRAGMENT_FILE" <<'PYEOF'
import json, os, sys
config_path, tunnel_conf, rt_conf, c_conf, fragment_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
with open(fragment_file) as f:
    raw = f.read()
frag = json.loads(raw)
with open(config_path) as f:
    config = json.load(f)
def priv_of(path):
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("private_key="):
                    return line.strip().split("=", 1)[1]
    except OSError:
        return None
    return None
kind = frag.get("kind")
if kind == "routetag":
    tag = frag.get("tag", "")
    if tag not in [o.get("tag") for o in config.get("outbounds", [])]:
        sys.exit("no such outbound: %s" % tag)
    found = 0
    for rule in config.get("routing", {}).get("rules", []):
        if "inboundTag" in rule and "domain" not in rule and "ip" not in rule:
            rule["outboundTag"] = tag
            found += 1
    if found != 1:
        sys.exit("expected one catch-all rule, found %d" % found)
elif kind in ("outbound", "inbound"):
    priv = priv_of(tunnel_conf) if "@TUNNEL_PRIVATE_KEY@" in raw else None
    rt_priv = priv_of(rt_conf) if ("@REALITY_PRIVATE_KEY@" in raw and rt_conf) else None
    c_priv = priv_of(c_conf) if ("@TUNNEL_C_PRIVATE_KEY@" in raw and c_conf) else None
    if "@TUNNEL_PRIVATE_KEY@" in raw and not priv:
        sys.exit("no private key in the tunnel config")
    if "@REALITY_PRIVATE_KEY@" in raw and not rt_priv:
        sys.exit("no private key in the Tunnel B config")
    if "@TUNNEL_C_PRIVATE_KEY@" in raw and not c_priv:
        sys.exit("no private key in the Tunnel C config")
    def sub(value):
        if isinstance(value, str):
            if priv:
                value = value.replace("@TUNNEL_PRIVATE_KEY@", priv)
            if rt_priv:
                value = value.replace("@REALITY_PRIVATE_KEY@", rt_priv)
            if c_priv:
                value = value.replace("@TUNNEL_C_PRIVATE_KEY@", c_priv)
            return value
        if isinstance(value, list):
            return [sub(v) for v in value]
        if isinstance(value, dict):
            return {k: sub(v) for k, v in value.items()}
        return value
    obj = sub(frag["object"])
    key = "outbounds" if kind == "outbound" else "inbounds"
    items = config.setdefault(key, [])
    for i, item in enumerate(items):
        if item.get("tag") == obj["tag"]:
            items[i] = obj
            break
    else:
        items.append(obj)
    # Tunnel C's exit inbound must egress: add its tag to the tunnel->direct
    # routing rule (the rule that already carries the other tunnel inbounds).
    route_to = frag.get("route_to")
    if route_to:
        matched = 0
        for rule in config.get("routing", {}).get("rules", []):
            if rule.get("outboundTag") == route_to and isinstance(rule.get("inboundTag"), list):
                if obj["tag"] not in rule["inboundTag"]:
                    rule["inboundTag"].append(obj["tag"])
                matched += 1
        if matched != 1:
            sys.exit("expected one %s routing rule, found %d" % (route_to, matched))
else:
    sys.exit("unknown fragment kind: %r" % (kind,))
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PYEOF
[ $? -eq 0 ] || exit 64
"$BIN" check "$SERVER_CONFIG" >/dev/null 2>&1 || { echo "the tunnel config was rejected" >&2; exit 62; }
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl restart "$SERVICE"
i=0
while [ $i -lt 12 ]; do
  if systemctl is-active --quiet "$SERVICE"; then break; fi
  i=$((i+1)); sleep 1
done
if ! systemctl is-active --quiet "$SERVICE"; then
  journalctl -u "$SERVICE" -n 25 --no-pager >&2 || true
  exit 63
fi
echo "tunnel=up"
"#;

/// Read the tunnel state from the server's own management API. Prints
/// `tunnel=up` and the raw `body=` when the endpoint answers, `tunnel=down`
/// when the service answers without it, `tunnel=missing` when the program is
/// too old to have the endpoint. Also prints Tunnel B's and Tunnel C's
/// independent state: `tunnel_b_key=1/0`, `tunnel_b_config=1/0`,
/// `tunnel_c_key=1/0`, `tunnel_c_config=1/0` (key material present, config
/// carries it). The caller parses the body.
pub const TUNNEL_STATUS: &str = r#"
install -d -m 700 "$WORK"
if [ -f /etc/zray/tunnel-rt.conf ]; then echo "tunnel_b_key=1"; else echo "tunnel_b_key=0"; fi
if [ -f /etc/zray/server.json ] && grep -q '"reality-tunnel"\|"tunnel-rt-in"' /etc/zray/server.json 2>/dev/null; then echo "tunnel_b_config=1"; else echo "tunnel_b_config=0"; fi
if [ -f /etc/zray/tunnel-c.conf ]; then echo "tunnel_c_key=1"; else echo "tunnel_c_key=0"; fi
if [ -f /etc/zray/server.json ] && grep -q '"tunnel-c"\|"tunnel-c-in"' /etc/zray/server.json 2>/dev/null; then echo "tunnel_c_config=1"; else echo "tunnel_c_config=0"; fi
code=$(curl -s -o "$WORK/tunnel.json" -w '%{http_code}' --max-time 8 -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "http://127.0.0.1:$MANAGEMENT_PORT/tunnel" 2>/dev/null || echo 000)
if [ "$code" = 200 ]; then
  echo "tunnel=up"
  printf 'body='
  tr -d '\n' < "$WORK/tunnel.json"
  echo
elif [ "$code" = 404 ]; then
  echo "tunnel=missing"
else
  echo "tunnel=down"
fi
rm -f "$WORK/tunnel.json"
"#;

/// Open the tunnel UDP port on the exit server, but only for the gateway's
/// IP. Never turns a firewall on; additive and idempotent. `TUNNEL_PORT` is
/// the port, `GW_IP` the gateway's address. Prints `firewall=`.
pub const FIREWALL_TUNNEL: &str = r#"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  if ! ufw status 2>/dev/null | grep -q "$TUNNEL_PORT/udp.*ALLOW.*$GW_IP"; then
    ufw allow from "$GW_IP" to any port "$TUNNEL_PORT" proto udp >/dev/null
  fi
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  rule="rule family=ipv4 source address=$GW_IP port port=$TUNNEL_PORT protocol=udp accept"
  if ! firewall-cmd --permanent --query-rich-rule="$rule" >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule="$rule" >/dev/null
    firewall-cmd --reload >/dev/null
  fi
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
"#;

/// Ask an IP-echo service for this machine's public address, for the exit
/// egress check. Empty output means it did not answer; the caller then
/// reports the egress as unverified instead of failing the install.
pub const EGRESS_IP: &str = r#"
curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true
"#;

/// Generate the exit's Tunnel B REALITY keypair with the installed server
/// program (`zray x25519`: URL-safe base64, no pad) and store it in
/// `$TUNNEL_RT_CONF` (mode 640, `root:$SVC_USER`). Only the public half is
/// printed; the private half never leaves the server. Prints `public_key=`.
/// Exit 60 when the tool fails.
pub const RT_KEYGEN: &str = r#"
out=$("$BIN" x25519 2>/dev/null || "$BIN" tools x25519 2>/dev/null) || { echo "the key tool failed" >&2; exit 60; }
priv=$(printf '%s\n' "$out" | sed -n 's/^PrivateKey: //p')
pub=$(printf '%s\n' "$out" | sed -n 's/^Password (PublicKey): //p')
[ -n "$priv" ] && [ -n "$pub" ] || { echo "the key tool printed no keys" >&2; exit 60; }
printf 'private_key=%s\npublic_key=%s\n' "$priv" "$pub" > "$TUNNEL_RT_CONF.new"
chmod 640 "$TUNNEL_RT_CONF.new"
chown "root:$SVC_USER" "$TUNNEL_RT_CONF.new"
mv -f "$TUNNEL_RT_CONF.new" "$TUNNEL_RT_CONF"
echo "public_key=$pub"
"#;

/// Read this server's Tunnel B public key back (for re-linking without key
/// rotation). Prints `public_key=`. Exit 61 when there is none.
pub const TUNNEL_RT_PUBKEY: &str = r#"
pub=$(sed -n 's/^public_key=//p' "$TUNNEL_RT_CONF" 2>/dev/null)
[ -n "$pub" ] || { echo "no Tunnel B key on this server" >&2; exit 61; }
echo "public_key=$pub"
"#;

/// Open Tunnel B's TCP port on the exit server, but only for the gateway's
/// IP — the mirror of [`FIREWALL_TUNNEL`]. Never turns a firewall on;
/// additive and idempotent. `RT_PORT` is the port, `GW_IP` the gateway's
/// address. Prints `firewall=`.
pub const FIREWALL_TUNNEL_RT: &str = r#"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  if ! ufw status 2>/dev/null | grep -q "$RT_PORT/tcp.*ALLOW.*$GW_IP"; then
    ufw allow from "$GW_IP" to any port "$RT_PORT" proto tcp >/dev/null
  fi
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  rule="rule family=ipv4 source address=$GW_IP port port=$RT_PORT protocol=tcp accept"
  if ! firewall-cmd --permanent --query-rich-rule="$rule" >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule="$rule" >/dev/null
    firewall-cmd --reload >/dev/null
  fi
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
"#;

/// Open the exit's Tunnel C UDP port, source-restricted to the gateway's
/// IPv6 address (`$GW6`, `$C_PORT`). Mirrors [`FIREWALL_TUNNEL`] on the v6
/// family: ufw matches the v6 source automatically, firewalld needs the
/// explicit `family=ipv6` rich rule. Additive only, like the others.
pub const FIREWALL_TUNNEL_C: &str = r#"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  if ! ufw status 2>/dev/null | grep -q "$C_PORT/udp.*ALLOW.*$GW6"; then
    ufw allow from "$GW6" to any port "$C_PORT" proto udp >/dev/null
  fi
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  rule="rule family=ipv6 source address=$GW6 port port=$C_PORT protocol=udp accept"
  if ! firewall-cmd --permanent --query-rich-rule="$rule" >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule="$rule" >/dev/null
    firewall-cmd --reload >/dev/null
  fi
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
"#;

/// Probe real end-to-end IPv6 usability on a server. Every line is an
/// observed fact, never an assumption:
/// - `ipv6_addr=`: a global-scope IPv6 address, or empty (link-local and
///   ULA do not count — they cannot reach the other server).
/// - `ipv6_default_route=1/0`: a v6 default route exists.
/// - `ipv6_mtu=`: the default route's MTU, or empty when not reported.
/// - `ipv6_egress=`: the public IPv6 address a real outbound HTTPS request
///   over v6 returned, or empty when the request failed.
/// - `ipv6_firewall=`: which firewall manages v6 here (report only).
///
/// The caller (install) decides the verdict; this script never does.
pub const IPV6_PROBE: &str = r#"
addr=$(ip -6 addr show scope global 2>/dev/null | sed -n 's/.*inet6 \([0-9a-fA-F:]*\)\/.*/\1/p' | head -1)
echo "ipv6_addr=$addr"
if ip -6 route show default 2>/dev/null | grep -q .; then echo "ipv6_default_route=1"; else echo "ipv6_default_route=0"; fi
mtu=$(ip -6 route show default 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p' | head -1)
echo "ipv6_mtu=$mtu"
egress=$(curl -6 -fsS --max-time 12 https://api64.ipify.org 2>/dev/null || true)
echo "ipv6_egress=$egress"
fw="none"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then fw="ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then fw="firewalld"
elif ip6tables -L -n 2>/dev/null | grep -q .; then fw="ip6tables"; fi
echo "ipv6_firewall=$fw"
"#;

/// Open a TCP connection from the gateway to `$HOST:$PORT` (Tunnel B's
/// exit port). Proves the path is open, not the REALITY handshake. Exit 70
/// when the port does not answer within 10 seconds.
pub const TCP_DIAL: &str = r#"
if command -v nc >/dev/null 2>&1; then
  nc -z -w10 "$HOST" "$PORT" >/dev/null 2>&1 || { echo "tcp dial to $HOST:$PORT failed" >&2; exit 70; }
else
  timeout 10 bash -c "cat < /dev/null > /dev/tcp/$HOST/$PORT" 2>/dev/null || { echo "tcp dial to $HOST:$PORT failed" >&2; exit 70; }
fi
echo "tcp=open"
"#;

// ---------------------------------------------------------------------------
// Huawei modem L2TP server (gateway role, Design G).
// ---------------------------------------------------------------------------

/// Install xl2tpd and ppp from the distro packages. Idempotent: missing
/// packages are installed, present ones are left alone. Exit 40 when there
/// is no package manager or the install fails.
pub const MODEM_PACKAGES: &str = r#"
need=""
command -v xl2tpd >/dev/null 2>&1 || need="$need xl2tpd"
command -v pppd >/dev/null 2>&1 || need="$need ppp"
[ -n "$need" ] || { echo "packages=present"; exit 0; }
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >&2
  apt-get install -y -qq $need >&2 || { echo "package install failed:$need" >&2; exit 40; }
elif command -v dnf >/dev/null 2>&1; then dnf install -y -q $need >&2 || exit 40
elif command -v yum >/dev/null 2>&1; then yum install -y -q $need >&2 || exit 40
else echo "no package manager to install:$need" >&2; exit 40; fi
echo "packages=installed"
"#;

/// Open UDP 1701 (L2TP) on the gateway. The modem sits behind CGNAT, so no
/// source restriction is possible (Design G section g.6). Additive and
/// idempotent; never turns a firewall on. Prints `firewall=`.
pub const MODEM_FIREWALL: &str = r#"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^status: active'; then
  ufw allow 1701/udp >/dev/null 2>&1 || true
  echo "firewall=ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  firewall-cmd --permanent --add-port=1701/udp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  echo "firewall=firewalld"
else
  echo "firewall=none"
fi
"#;

/// Enable and start xl2tpd. Prints `active=1` when the service is up,
/// `active=0` otherwise (the caller decides whether that is fatal).
pub const MODEM_ENABLE: &str = r#"
systemctl enable --now xl2tpd >/dev/null 2>&1 || true
if systemctl is-active --quiet xl2tpd 2>/dev/null; then echo "active=1"; else echo "active=0"; fi
"#;

/// Report the modem server's state: `modem_active=1/0` (xl2tpd running),
/// `modem_config=1/0` (our xl2tpd.conf present), and one `session=` line
/// per live PPP session (`user@address`).
pub const MODEM_STATUS: &str = r#"
if [ -f /etc/xl2tpd/xl2tpd.conf ]; then echo "modem_config=1"; else echo "modem_config=0"; fi
if systemctl is-active --quiet xl2tpd 2>/dev/null; then echo "modem_active=1"; else echo "modem_active=0"; fi
for pid in $(pgrep -x pppd 2>/dev/null); do
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  user=$(printf '%s' "$cmd" | sed -n 's/.*user \([^ ]*\).*/\1/p')
  ip=$(ip -o addr show 2>/dev/null | awk -v pid="$pid" '/ppp/ {print $4}' | head -1)
  [ -n "$user" ] || user="unknown"
  echo "session=$user@$ip"
done
"#;

/// Fail-closed guard for the modem pool: drop forwarded packets from
/// `$POOL` until the routing agent confirms the TUN handoff contract
/// (Design G Q2). Without this, a future `ip_forward=1` would let modem
/// traffic exit via the main table — unclassified direct egress. The
/// pppd options already carry `nodefaultroute`; this is the second layer.
/// Idempotent. Prints `guard=1` when the rule is in place.
pub const MODEM_POOL_GUARD: &str = r#"
if command -v iptables >/dev/null 2>&1; then
  if ! iptables -C FORWARD -s "$POOL" -j DROP >/dev/null 2>&1; then
    iptables -I FORWARD 1 -s "$POOL" -j DROP >/dev/null 2>&1 || true
  fi
  if iptables -C FORWARD -s "$POOL" -j DROP >/dev/null 2>&1; then echo "guard=1"; else echo "guard=0"; fi
else
  echo "guard=0"
fi
"#;

/// Remove the pool guard again (used by teardown, and when the TUN handoff
/// lands). Idempotent.
pub const MODEM_POOL_UNGUARD: &str = r#"
if command -v iptables >/dev/null 2>&1; then
  while iptables -C FORWARD -s "$POOL" -j DROP >/dev/null 2>&1; do
    iptables -D FORWARD -s "$POOL" -j DROP >/dev/null 2>&1 || break
  done
fi
echo "guard=0"
"#;

/// Terminate the PPP session of `$USER` (account revocation/rotation).
/// Idempotent: missing sessions are not an error.
pub const MODEM_KILL_SESSION: &str = r#"
pkill -f "pppd.*user $USER" 2>/dev/null || true
sleep 1
if pgrep -f "pppd.*user $USER" >/dev/null 2>&1; then echo "killed=0"; else echo "killed=1"; fi
"#;

/// Delete the scratch directory.
pub const CLEAN: &str = r#"rm -rf "$WORK""#;

/// Read the live usage figures from the server's own management API.
pub const USAGE: &str = r#"
curl -fsS --max-time 8 -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "http://127.0.0.1:$MANAGEMENT_PORT/usage"
"#;

/// Download a pinned archive and keep it only if its hash is `SHA`; unpack it
/// and leave the server program at `$WORK/program`. Exit 30 on a mismatch, 31
/// when the archive holds no program.
pub const FETCH_PINNED_ARCHIVE: &str = r#"
install -d -m 700 "$WORK"
curl -fL --max-time 900 -o "$WORK/archive.tar.gz" "https://github.com/$REPO/releases/download/$TAG/$ASSET"
got=$(sha256sum "$WORK/archive.tar.gz" | cut -d' ' -f1)
if [ "$got" != "$SHA" ]; then rm -f "$WORK/archive.tar.gz"; echo "checksum mismatch" >&2; exit 30; fi
rm -rf "$WORK/unpack"; install -d -m 700 "$WORK/unpack"
tar -xzf "$WORK/archive.tar.gz" -C "$WORK/unpack"
bin=$(find "$WORK/unpack" -maxdepth 1 -type f ! -name '*.toml' | head -n 1)
[ -n "$bin" ] || { echo "the archive holds no program" >&2; exit 31; }
mv -f "$bin" "$WORK/program"
chmod 755 "$WORK/program"
rm -rf "$WORK/unpack" "$WORK/archive.tar.gz"
"#;

/// The session lines of the MasterDNS server's own log since it last started.
/// They hold no address (the server logs none at its default level), only a
/// session number or a count, which is all the usage figure is built from.
pub const MASTERDNS_LOG: &str = r#"
since=$(systemctl show "$SERVICE" -p ActiveEnterTimestamp --value 2>/dev/null || true)
[ -n "$since" ] || exit 0
journalctl -u "$SERVICE" --since "$since" -o short-unix --no-pager 2>/dev/null | grep -E "Session Created|Session Closed|Expired Sessions Cleaned" || true
"#;

#[cfg(test)]
mod key_tool_tests {
    use super::*;

    /// The server program's key tools are `zray wg` / `zray x25519` (Xray's
    /// names); `zray tools wg` does not exist. The scripts once called only
    /// the latter, so every tunnel install stopped at "the key tool failed".
    #[test]
    fn add_key_never_glues_a_key_onto_the_previous_line() {
        assert!(ADD_KEY.contains(r#"tail -c1 "$ak""#));
    }

    #[test]
    fn key_scripts_call_the_real_subcommands() {
        assert!(WG_KEYGEN.contains(r#""$BIN" wg"#));
        assert!(RT_KEYGEN.contains(r#""$BIN" x25519"#));
    }
}
