#!/usr/bin/env bash
# End-to-end test. It REALLY HARDENS THE MACHINE IT RUNS ON, so use a throwaway Ubuntu 22.04 or
# 24.04 VM (CI uses the GitHub-hosted runners). Needs: ansible-core, jq, sudo without a password.
#
#   tests/run.sh
#
# What it proves, in order:
#   1. the audit script is not vacuous: on a vanilla machine it fails on many checks
#   2. the lockout guard refuses to switch password logins off on a host without authorized_keys
#   3. converging makes the audit pass
#   4. converging again changes nothing (idempotence)
#   5. each kind of drift is noticed by the audit and repaired by the next run
#   6. sshd still accepts its configuration and the firewall table is still loaded
set -euo pipefail

cd "$(dirname "$0")/.."
AUDIT=audit/hardening-audit.sh
PLAY=(ansible-playbook -i 'localhost,' -c local site.yml -e ansible_python_interpreter=/usr/bin/python3)
MIN_VANILLA_FAILS=10

phase() { printf '\n==== %s\n' "$*"; }
die() { printf 'TEST FAILED: %s\n' "$*" >&2; exit 1; }

audit() { sudo "$AUDIT" "$@"; }

converge() { "${PLAY[@]}" -e '{"ssh_lockout_guard": false}'; }

phase "1. vanilla machine: the audit has to find a lot to complain about"
audit --json > before.json || true
fails="$(jq '.summary.fail' before.json)"
printf 'failed checks before hardening: %s (need at least %s)\n' "$fails" "$MIN_VANILLA_FAILS"
jq -r '.results[] | select(.status == "FAIL") | "  \(.id)"' before.json | head -n 15
[ "$fails" -ge "$MIN_VANILLA_FAILS" ] || die "the audit only found $fails problems on an unhardened machine"

phase "2. lockout guard"
# Point the guard at an empty directory, so the test does not depend on which keys the machine has.
empty_dir="$(mktemp -d)"
if out="$("${PLAY[@]}" -e "{\"ssh_lockout_guard_paths\": [\"$empty_dir\"]}" 2>&1)"; then
  printf '%s\n' "$out"
  die "the playbook went ahead although nobody has an authorized_keys file"
fi
grep -q 'lock everybody out' <<<"$out" || { printf '%s\n' "$out"; die "the playbook failed, but not because of the lockout guard"; }
[ ! -e /etc/ssh/sshd_config.d/00-hardening.conf ] || die "the guard fired too late: sshd was already reconfigured"
rmdir "$empty_dir"
echo "refused, and sshd was not reconfigured: ok"

phase "3. converge, then audit"
converge
audit

phase "4. idempotence: a second run must change nothing"
out="$(converge 2>&1)" || { printf '%s\n' "$out"; die "second run failed"; }
printf '%s\n' "$out" | tail -n 4
grep -Eq 'ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' <<<"$out" || die "second run changed something"

phase "5. drift is noticed and repaired"
# mutation  <check id>  <what to break>
mutation() {
  local id="$1" cmd="$2" group="${1%%-*}"
  printf '\n-- %s: %s\n' "$id" "$cmd"
  sudo bash -c "$cmd"
  sudo "$AUDIT" --json --only "$group" | jq -e --arg id "$id" '.results[] | select(.id == $id and .status == "FAIL")' > /dev/null \
    || die "$id was not reported after: $cmd"
  echo "audit reports $id as FAIL"
  converge > /dev/null || die "converge failed while repairing $id"
  sudo "$AUDIT" --only "$group" > /dev/null || { sudo "$AUDIT" --only "$group" || true; die "$id was not repaired"; }
  echo "next run repaired it, audit is clean again"
}

mutation ssh-permitrootlogin "sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config.d/00-hardening.conf"
mutation sysctl-net.ipv4.tcp_syncookies "sysctl -w net.ipv4.tcp_syncookies=0"
mutation fw-table "nft delete table inet hardening"
mutation perm-group "chmod 666 /etc/group"
mutation acct-pass-max-days "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 99999/' /etc/login.defs"
mutation svc-pkg-telnet "DEBIAN_FRONTEND=noninteractive apt-get install -y -q telnet"
mutation mod-cramfs "rm /etc/modprobe.d/60-hardening.conf"
mutation audit-rules-identity "auditctl -D"
mutation upd-unattended "rm /etc/apt/apt.conf.d/51hardening-periodic"

phase "6. the machine still works"
sudo sshd -t && echo "sshd -t: ok"
sudo nft list table inet hardening > /dev/null && echo "firewall table: loaded"
audit | tail -n 3

printf '\nALL GOOD\n'
