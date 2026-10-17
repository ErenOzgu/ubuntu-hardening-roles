#!/usr/bin/env bash
# hardening-audit.sh: read-only check of an Ubuntu host against the baseline that the roles in
# this repository apply.
#
# It looks at the state the system is actually in (sshd -T, sysctl, nft, dpkg, systemctl, ...)
# and never reads the Ansible variables, so it is an independent check: it also works on a host
# that was hardened some other way, and it notices drift after the playbook has been run.
#
#   sudo audit/hardening-audit.sh                  # human-readable report
#   sudo audit/hardening-audit.sh --json           # the same as JSON
#   sudo audit/hardening-audit.sh --only ssh,fw    # only these groups
#
# Groups: ssh sysctl fw acct perm audit upd mod svc
# Exit status: 0 nothing failed, 1 at least one check failed, 2 bad usage or not root.
# The only thing it ever writes is an empty /run/sshd, which sshd -T insists on and which sshd
# itself creates on start.

set -u
set -o pipefail

JSON=0
ONLY=""
ROOT_CHECK=1

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --only) shift; ONLY="${1:-}" ;;
    --no-root-check) ROOT_CHECK=0 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$ROOT_CHECK" = 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "hardening-audit.sh needs root to read the effective configuration (try sudo)." >&2
  exit 2
fi

R_ID=()
R_STATUS=()
R_DESC=()
R_DETAIL=()
n_pass=0
n_fail=0
n_skip=0

want_group() {
  [ -z "$ONLY" ] && return 0
  local group="${1%%-*}"
  case ",$ONLY," in *",$group,"*) return 0 ;; esac
  return 1
}

record() { # id status description detail
  want_group "$1" || return 0
  R_ID+=("$1")
  R_STATUS+=("$2")
  R_DESC+=("$3")
  R_DETAIL+=("${4:-}")
  case "$2" in
    PASS) n_pass=$((n_pass + 1)) ;;
    FAIL) n_fail=$((n_fail + 1)) ;;
    SKIP) n_skip=$((n_skip + 1)) ;;
  esac
}

ok() { record "$1" PASS "$2" "${3:-}"; }
bad() { record "$1" FAIL "$2" "${3:-}"; }
skip() { record "$1" SKIP "$2" "${3:-}"; }

is_int() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

check_eq() { # id description actual expected
  if [ "$3" = "$4" ]; then ok "$1" "$2" "$3"; else bad "$1" "$2" "found '${3:-<unset>}', want '$4'"; fi
}

check_le() { # id description actual max
  if is_int "$3" && [ "$3" -le "$4" ]; then ok "$1" "$2" "$3"; else bad "$1" "$2" "found '${3:-<unset>}', want <= $4"; fi
}

check_ge() { # id description actual min
  if is_int "$3" && [ "$3" -ge "$4" ]; then ok "$1" "$2" "$3"; else bad "$1" "$2" "found '${3:-<unset>}', want >= $4"; fi
}

check_absent() { # id description text regex
  local hit
  hit="$(grep -Eio "$4" <<<"$3" | sort -u | paste -sd, -)"
  if [ -z "$hit" ]; then ok "$1" "$2"; else bad "$1" "$2" "found: $hit"; fi
}

# ---------------------------------------------------------------------------------------- ssh
SSHD_T=""
SSHD_STATE=missing
if command -v sshd >/dev/null 2>&1; then
  [ -d /run/sshd ] || mkdir -p /run/sshd
  if SSHD_T="$(sshd -T 2>/dev/null)"; then SSHD_STATE=ok; else SSHD_STATE=broken; fi
fi
sshd_val() { awk -v k="$1" '$1 == k { sub(/^[^ ]+ /, ""); print; exit }' <<<"$SSHD_T"; }

if [ "$SSHD_STATE" = ok ]; then
  check_eq ssh-permitrootlogin 'root cannot log in over ssh' "$(sshd_val permitrootlogin)" no
  check_eq ssh-passwordauthentication 'password logins are off' "$(sshd_val passwordauthentication)" no
  check_eq ssh-kbdinteractiveauthentication 'keyboard-interactive logins are off' "$(sshd_val kbdinteractiveauthentication)" no
  check_eq ssh-permitemptypasswords 'empty passwords are refused' "$(sshd_val permitemptypasswords)" no
  check_eq ssh-hostbasedauthentication 'host-based authentication is off' "$(sshd_val hostbasedauthentication)" no
  check_eq ssh-permituserenvironment 'users cannot set the environment' "$(sshd_val permituserenvironment)" no
  check_le ssh-maxauthtries 'at most 4 authentication attempts' "$(sshd_val maxauthtries)" 4
  check_le ssh-logingracetime 'login grace time is 60 s or less' "$(sshd_val logingracetime)" 60
  check_ge ssh-clientaliveinterval 'idle sessions are probed' "$(sshd_val clientaliveinterval)" 1
  check_le ssh-clientaliveinterval-max 'idle probe interval is 300 s or less' "$(sshd_val clientaliveinterval)" 300
  check_le ssh-clientalivecountmax 'at most 3 unanswered idle probes' "$(sshd_val clientalivecountmax)" 3
  check_eq ssh-x11forwarding 'X11 forwarding is off' "$(sshd_val x11forwarding)" no
  check_eq ssh-allowagentforwarding 'agent forwarding is off' "$(sshd_val allowagentforwarding)" no
  check_eq ssh-allowtcpforwarding 'TCP forwarding is off' "$(sshd_val allowtcpforwarding)" no
  check_eq ssh-loglevel 'log level is VERBOSE' "$(sshd_val loglevel)" VERBOSE
  check_absent ssh-ciphers 'no weak ciphers' "$(sshd_val ciphers)" '[a-z0-9-]*(cbc|3des|arcfour|blowfish|cast128)[a-z0-9@.-]*'
  check_absent ssh-macs 'no weak MACs' "$(sshd_val macs)" 'hmac-md5[a-z0-9@.-]*|hmac-sha1[a-z0-9@.-]*|umac-64[a-z0-9@.-]*'
  check_absent ssh-kexalgorithms 'no weak key exchange' "$(sshd_val kexalgorithms)" \
    'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1'
  banner="$(sshd_val banner)"
  if [ -n "$banner" ] && [ "$banner" != none ]; then ok ssh-banner 'a login banner is set' "$banner"; else bad ssh-banner 'a login banner is set' 'none'; fi
elif [ "$SSHD_STATE" = broken ]; then
  bad ssh-config 'sshd accepts its configuration' 'sshd -T failed'
else
  skip ssh-config 'sshd is installed' 'openssh-server is not installed'
fi

# ------------------------------------------------------------------------------------- sysctl
# key|operator|value. "eq" is exact, "ge" means at least. A key the kernel does not have is skipped.
SYSCTL_CHECKS=(
  'fs.protected_fifos|ge|2'
  'fs.protected_hardlinks|eq|1'
  'fs.protected_regular|ge|2'
  'fs.protected_symlinks|eq|1'
  'fs.suid_dumpable|eq|0'
  'kernel.dmesg_restrict|eq|1'
  'kernel.kexec_load_disabled|eq|1'
  'kernel.kptr_restrict|ge|2'
  'kernel.randomize_va_space|eq|2'
  'kernel.sysrq|eq|0'
  'kernel.unprivileged_bpf_disabled|ge|1'
  'kernel.yama.ptrace_scope|ge|1'
  'net.core.bpf_jit_harden|ge|2'
  'net.ipv4.conf.all.accept_redirects|eq|0'
  'net.ipv4.conf.all.accept_source_route|eq|0'
  'net.ipv4.conf.all.log_martians|eq|1'
  'net.ipv4.conf.all.rp_filter|eq|1'
  'net.ipv4.conf.all.secure_redirects|eq|0'
  'net.ipv4.conf.all.send_redirects|eq|0'
  'net.ipv4.conf.default.accept_redirects|eq|0'
  'net.ipv4.conf.default.accept_source_route|eq|0'
  'net.ipv4.conf.default.log_martians|eq|1'
  'net.ipv4.conf.default.rp_filter|eq|1'
  'net.ipv4.conf.default.secure_redirects|eq|0'
  'net.ipv4.conf.default.send_redirects|eq|0'
  'net.ipv4.icmp_echo_ignore_broadcasts|eq|1'
  'net.ipv4.icmp_ignore_bogus_error_responses|eq|1'
  'net.ipv4.tcp_rfc1337|eq|1'
  'net.ipv4.tcp_syncookies|eq|1'
  'net.ipv6.conf.all.accept_redirects|eq|0'
  'net.ipv6.conf.all.accept_source_route|eq|0'
  'net.ipv6.conf.default.accept_redirects|eq|0'
  'net.ipv6.conf.default.accept_source_route|eq|0'
)
for entry in "${SYSCTL_CHECKS[@]}"; do
  IFS='|' read -r key op want <<<"$entry"
  if ! have="$(sysctl -n "$key" 2>/dev/null)"; then
    skip "sysctl-$key" "$key is set" 'not available on this kernel'
    continue
  fi
  if [ "$op" = ge ]; then
    check_ge "sysctl-$key" "$key >= $want" "$have" "$want"
  else
    check_eq "sysctl-$key" "$key = $want" "$have" "$want"
  fi
done

# ---------------------------------------------------------------------------------- firewall
if command -v nft >/dev/null 2>&1 && nft list table inet hardening >/dev/null 2>&1; then
  ok fw-table 'the hardening nftables table is loaded'
  chain="$(nft list chain inet hardening input 2>/dev/null)"
  if grep -q 'policy drop' <<<"$chain"; then ok fw-policy 'inbound traffic is dropped by default'; else bad fw-policy 'inbound traffic is dropped by default' 'policy is not drop'; fi
  if grep -q 'ct state established,related accept' <<<"$chain"; then
    ok fw-established 'replies to our own traffic are accepted'
  else
    bad fw-established 'replies to our own traffic are accepted' 'rule missing'
  fi
  ssh_port="$(sshd_val port)"
  ssh_port="${ssh_port:-22}"
  if grep -Eq "tcp dport $ssh_port " <<<"$chain"; then
    ok fw-ssh "ssh (port $ssh_port) is reachable"
  else
    bad fw-ssh "ssh (port $ssh_port) is reachable" 'no accept rule'
  fi
else
  bad fw-table 'the hardening nftables table is loaded' 'nft is missing or the table is not loaded'
fi
boot_fw=""
for unit in hardening-firewall.service nftables.service ufw.service; do
  if [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = enabled ]; then boot_fw="$unit"; break; fi
done
if [ -n "$boot_fw" ]; then ok fw-boot 'a firewall is enabled at boot' "$boot_fw"; else bad fw-boot 'a firewall is enabled at boot' 'none of hardening-firewall, nftables, ufw'; fi

# ------------------------------------------------------------------------------------ accounts
login_defs() { awk -v k="$1" '$1 == k { v = $2 } END { print v }' /etc/login.defs; }
pwq() { grep -rhsE "^[[:space:]]*$1[[:space:]]*=" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ | tail -1 | sed -E 's/.*=[[:space:]]*//'; }

check_le acct-pass-max-days 'passwords expire within 365 days' "$(login_defs PASS_MAX_DAYS)" 365
check_ge acct-pass-min-days 'passwords cannot be changed more than once a day' "$(login_defs PASS_MIN_DAYS)" 1
umask_value="$(login_defs UMASK)"
if [[ "$umask_value" =~ ^[0-7]{3,4}$ ]] && [ $((8#$umask_value & 8#027)) -eq $((8#027)) ]; then
  ok acct-umask 'the default umask is 027 or stricter' "$umask_value"
else
  bad acct-umask 'the default umask is 027 or stricter' "found '${umask_value:-<unset>}'"
fi
check_ge acct-pwquality-minlen 'passwords need at least 14 characters' "$(pwq minlen)" 14
check_ge acct-pwquality-minclass 'passwords need at least 3 character classes' "$(pwq minclass)" 3
if grep -qs 'pam_pwquality' /etc/pam.d/common-password; then
  ok acct-pwquality-pam 'pam_pwquality is in the password stack'
else
  bad acct-pwquality-pam 'pam_pwquality is in the password stack' 'not found in /etc/pam.d/common-password'
fi
if grep -rhsE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0[[:space:]]*$' /etc/security/limits.conf /etc/security/limits.d/ >/dev/null; then
  ok acct-core-dumps 'core dumps are limited to 0 bytes'
else
  bad acct-core-dumps 'core dumps are limited to 0 bytes' 'no "* hard core 0" line'
fi
empty="$(awk -F: '$2 == "" { print $1 }' /etc/shadow 2>/dev/null | paste -sd, -)"
if [ -z "$empty" ]; then ok acct-no-empty-passwords 'no account has an empty password'; else bad acct-no-empty-passwords 'no account has an empty password' "$empty"; fi
uid0="$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | paste -sd, -)"
check_eq acct-single-uid0 'root is the only account with UID 0' "$uid0" root

# ------------------------------------------------------------------------------- permissions
mode_ok() { # id path max_mode owner
  local path="$2" max="$3" owner="$4" mode have_owner
  if [ ! -e "$path" ]; then skip "$1" "$path permissions" 'does not exist'; return; fi
  mode="$(stat -c '%a' "$path")"
  have_owner="$(stat -c '%U' "$path")"
  if [ $((8#$mode & ~8#$max & 8#7777)) -eq 0 ] && [ "$have_owner" = "$owner" ]; then
    ok "$1" "$path is $max or stricter and owned by $owner" "$mode $have_owner"
  else
    bad "$1" "$path is $max or stricter and owned by $owner" "found mode $mode owner $have_owner"
  fi
}
mode_ok perm-crontab /etc/crontab 600 root
mode_ok perm-cron-hourly /etc/cron.hourly 700 root
mode_ok perm-cron-daily /etc/cron.daily 700 root
mode_ok perm-cron-weekly /etc/cron.weekly 700 root
mode_ok perm-cron-monthly /etc/cron.monthly 700 root
mode_ok perm-cron-d /etc/cron.d 700 root
mode_ok perm-sshd-config /etc/ssh/sshd_config 600 root
mode_ok perm-shadow /etc/shadow 640 root
mode_ok perm-gshadow /etc/gshadow 640 root
mode_ok perm-passwd /etc/passwd 644 root
mode_ok perm-group /etc/group 644 root

# ------------------------------------------------------------------------------------ auditd
pkg_installed() { [ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | cut -c1-2)" = ii ]; }

if pkg_installed auditd; then
  ok audit-installed 'auditd is installed'
  if [ "$(systemctl is-active auditd 2>/dev/null)" = active ]; then ok audit-running 'auditd is running'; else bad audit-running 'auditd is running' 'not active'; fi
  loaded="$(auditctl -l 2>/dev/null)"
  if grep -q -- '-k identity' <<<"$loaded"; then ok audit-rules-identity 'changes to account files are audited'; else bad audit-rules-identity 'changes to account files are audited' 'rule not loaded'; fi
  if grep -q -- '-k time-change' <<<"$loaded"; then ok audit-rules-time 'changes to the clock are audited'; else bad audit-rules-time 'changes to the clock are audited' 'rule not loaded'; fi
  if grep -rqs -- '-k identity' /etc/audit/rules.d/; then ok audit-rules-persisted 'the rules survive a reboot'; else bad audit-rules-persisted 'the rules survive a reboot' 'nothing in /etc/audit/rules.d'; fi
else
  bad audit-installed 'auditd is installed' 'package missing'
fi

# ------------------------------------------------------------------------------------ updates
if pkg_installed unattended-upgrades; then ok upd-package 'unattended-upgrades is installed'; else bad upd-package 'unattended-upgrades is installed' 'package missing'; fi
apt_dump="$(apt-config dump 2>/dev/null)"
if grep -q 'APT::Periodic::Update-Package-Lists "1"' <<<"$apt_dump"; then
  ok upd-lists 'package lists are refreshed daily'
else
  bad upd-lists 'package lists are refreshed daily' 'APT::Periodic::Update-Package-Lists is not "1"'
fi
if grep -q 'APT::Periodic::Unattended-Upgrade "1"' <<<"$apt_dump"; then
  ok upd-unattended 'unattended upgrades run daily'
else
  bad upd-unattended 'unattended upgrades run daily' 'APT::Periodic::Unattended-Upgrade is not "1"'
fi
if grep -i 'Allowed-Origins' <<<"$apt_dump" | grep -qi security; then
  ok upd-security 'security updates are among the allowed origins'
else
  bad upd-security 'security updates are among the allowed origins' 'no -security origin'
fi

# ---------------------------------------------------------------------------- kernel modules
for module in cramfs freevxfs hfs hfsplus jffs2 dccp sctp rds tipc; do
  if modprobe -n -v "$module" 2>&1 | grep -Eq 'install[[:space:]]+(/usr)?/bin/(true|false)'; then
    ok "mod-$module" "$module cannot be loaded"
  else
    bad "mod-$module" "$module cannot be loaded" 'no "install ... /bin/false" rule'
  fi
done

# ------------------------------------------------------------------------------------ services
for package in telnet rsh-client rsh-redone-client talk ntalk nis; do
  if pkg_installed "$package"; then bad "svc-pkg-$package" "$package is not installed" 'installed'; else ok "svc-pkg-$package" "$package is not installed"; fi
done
for unit in avahi-daemon cups cups-browsed isc-dhcp-server isc-dhcp-server6 slapd nfs-server rpcbind snmpd vsftpd; do
  if ! systemctl list-unit-files "$unit.service" 2>/dev/null | grep -q "^$unit.service"; then
    ok "svc-$unit" "$unit is not enabled or running" 'not installed'
    continue
  fi
  enabled="$(systemctl is-enabled "$unit.service" 2>/dev/null)"
  active="$(systemctl is-active "$unit.service" 2>/dev/null)"
  if [ "$enabled" != enabled ] && [ "$active" != active ]; then
    ok "svc-$unit" "$unit is not enabled or running" "$enabled, $active"
  else
    bad "svc-$unit" "$unit is not enabled or running" "$enabled, $active"
  fi
done

# ------------------------------------------------------------------------------------ report
jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n\t' '  '; }

if [ "$JSON" = 1 ]; then
  os_name="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unknown}")"
  printf '{"host":"%s","os":"%s","summary":{"pass":%d,"fail":%d,"skip":%d},"results":[' \
    "$(jesc "$(hostname)")" "$(jesc "$os_name")" "$n_pass" "$n_fail" "$n_skip"
  for i in "${!R_ID[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    printf '{"id":"%s","status":"%s","description":"%s","detail":"%s"}' \
      "$(jesc "${R_ID[$i]}")" "${R_STATUS[$i]}" "$(jesc "${R_DESC[$i]}")" "$(jesc "${R_DETAIL[$i]}")"
  done
  printf ']}\n'
else
  for i in "${!R_ID[@]}"; do
    line="$(printf '%-5s %-44s %s' "${R_STATUS[$i]}" "${R_ID[$i]}" "${R_DESC[$i]}")"
    if [ -n "${R_DETAIL[$i]}" ] && [ "${R_STATUS[$i]}" != PASS ]; then line="$line  [${R_DETAIL[$i]}]"; fi
    printf '%s\n' "$line"
  done
  printf '\n%d passed, %d failed, %d skipped\n' "$n_pass" "$n_fail" "$n_skip"
fi

[ "$n_fail" -eq 0 ]
