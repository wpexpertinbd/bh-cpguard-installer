#!/bin/bash
# ================================================================
#  cPGuard Unattended Installer for CWP Pro + AlmaLinux (v1.0)
#
#  Runs ON the target server. Handles the full BiswasHost install
#  workflow non-interactively:
#    1. Preflight (OS, CWP, Apache, disk, RAM, cPGuard already?)
#    2. Whitelist cPGuard call-home IPs in CWP firewall (csf/firewalld)
#    3. Drive the interactive installer via `expect` with the canonical
#       BiswasHost answers (apache / apache / vhosts / cpguard.conf / ...)
#    4. Patch /usr/local/apache/conf.d/mod_security.conf
#       (comment owasp-old, include cpguard.conf) — idempotent
#    5. Write the standard BiswasHost SecRuleRemoveById exclusions
#       to /etc/cpguard/custom-exclusions.conf (incl. rule 1006000)
#    6. Auto-migrate CSF rules if CSF detected
#    7. Apply license, enable WAF, enable auto-cleanup
#    8. Restart httpd
#    9. Verify (license active, WAF on, services up, no fatal modsec)
#
#  Usage:
#    bash cpguard-install.sh LICENSE-KEY
#
#  Or one-liner (from dispatcher or by hand):
#    curl -fsSL https://raw.githubusercontent.com/wpexpertinbd/bh-cpguard-installer/main/cpguard-install.sh \
#      | bash -s -- LICENSE-KEY
#
#  Idempotent. Safe to re-run. Logs to /var/log/bh-cpguard-install.log
# ================================================================

set -o pipefail

LICENSE="${1:-}"
EDITION="${CPGUARD_EDITION:-standard}"   # standard|lite
APPLY_EXCLUSIONS="${APPLY_EXCLUSIONS:-1}"
MIGRATE_CSF="${MIGRATE_CSF:-1}"
LOG=/var/log/bh-cpguard-install.log

# ---------- helpers ----------
log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
die()  { log "FATAL: $*"; exit 1; }
ok()   { log "OK:    $*"; }
warn() { log "WARN:  $*"; }

[ "$(id -u)" -eq 0 ] || die "Must run as root."
[ -n "$LICENSE" ] || die "Missing license key. Usage: bash $0 LICENSE-KEY"

mkdir -p "$(dirname "$LOG")"
: > /tmp/bh-cpg-summary.txt
SUMMARY_KV() { printf '%s=%s\n' "$1" "$2" >> /tmp/bh-cpg-summary.txt; }

log "================================================================"
log "BH cPGuard installer v1.0 starting on $(hostname)"
log "Edition: $EDITION | License: ${LICENSE:0:6}…${LICENSE: -4} | PID $$"
log "================================================================"

# ---------- 1. Preflight ----------
log "[1/9] Preflight..."

OS_REL=/etc/os-release
[ -f "$OS_REL" ] || die "Cannot read $OS_REL"
. "$OS_REL"
case "$ID" in
  almalinux|rocky|centos|rhel) ok "OS: $PRETTY_NAME" ;;
  *) die "Unsupported OS: $ID (expected almalinux/rocky/centos/rhel)" ;;
esac
SUMMARY_KV os "$PRETTY_NAME"

[ -d /usr/local/cwpsrv ] || die "CWP not detected (/usr/local/cwpsrv missing)"
ok "CWP detected"

# Apache detection: CWP often installs httpd at /usr/local/apache/bin/httpd
# without putting it in root's PATH. Check both locations.
HTTPD_BIN=""
if command -v httpd >/dev/null 2>&1; then
  HTTPD_BIN=$(command -v httpd)
elif [ -x /usr/local/apache/bin/httpd ]; then
  HTTPD_BIN=/usr/local/apache/bin/httpd
  # Add to PATH for the rest of the script (httpd -t check, etc.)
  export PATH="/usr/local/apache/bin:$PATH"
fi
[ -n "$HTTPD_BIN" ] || die "Apache httpd binary not found (checked PATH + /usr/local/apache/bin/)"
[ -d /usr/local/apache/conf.d ] || die "Apache conf.d missing — non-standard CWP build?"
ok "Apache present ($HTTPD_BIN)"

# CentOS 7 reached EOL on 2024-06-30 — official mirrors stopped serving it.
# Overwrite Base/EPEL/MariaDB repos with archive URLs so yum works again.
# See docs/centos7-repo-fix.md for the manual procedure if this misbehaves.
if [ "$ID" = "centos" ] && [ "${VERSION_ID%%.*}" = "7" ]; then
  warn "CentOS 7 is EOL (2024-06-30) — no upstream security updates."
  warn "Recommend client migrate to AlmaLinux 9 long-term."

  # Test if yum is already working. If 'yum makecache fast' fails on base/extras/
  # updates/epel, repoint those repos at the vault.
  if ! yum -q makecache fast --disablerepo='mariadb' >/dev/null 2>&1; then
    log "yum failing — repointing CentOS 7 repos to vault/archive..."

    # 1. CentOS Base/Updates/Extras → vault.centos.org
    if [ -f /etc/yum.repos.d/CentOS-Base.repo ] && \
       ! grep -q 'vault.centos.org' /etc/yum.repos.d/CentOS-Base.repo; then
      cp -a /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bh-preinstall
      cat > /etc/yum.repos.d/CentOS-Base.repo <<'REPO'
[base]
name=CentOS-7 - Base
baseurl=http://vault.centos.org/7.9.2009/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

[updates]
name=CentOS-7 - Updates
baseurl=http://vault.centos.org/7.9.2009/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

[extras]
name=CentOS-7 - Extras
baseurl=http://vault.centos.org/7.9.2009/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

[centosplus]
name=CentOS-7 - Plus
baseurl=http://vault.centos.org/7.9.2009/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
REPO
      ok "CentOS-Base.repo → vault.centos.org"
    fi

    # 2. EPEL → archives.fedoraproject.org
    if [ -f /etc/yum.repos.d/epel.repo ] && \
       ! grep -q 'archives.fedoraproject.org' /etc/yum.repos.d/epel.repo; then
      cp -a /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.bh-preinstall
      cat > /etc/yum.repos.d/epel.repo <<'REPO'
[epel]
name=Extra Packages for Enterprise Linux 7 - $basearch
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
REPO
      ok "epel.repo → archives.fedoraproject.org"
    fi

    # 3. MariaDB (10.x) → archive.mariadb.org. Preserve major version (10.3/4/5/6/11).
    if [ -f /etc/yum.repos.d/mariadb.repo ] && \
       grep -q 'yum.mariadb.org' /etc/yum.repos.d/mariadb.repo; then
      cp -a /etc/yum.repos.d/mariadb.repo /etc/yum.repos.d/mariadb.repo.bh-preinstall
      sed -i -E 's|http://yum\.mariadb\.org/(10\.[0-9]+)/centos7-amd64|https://archive.mariadb.org/mariadb-\1/yum/centos7-amd64|g' \
        /etc/yum.repos.d/mariadb.repo
      ok "mariadb.repo → archive.mariadb.org"
    fi

    yum clean all >/dev/null 2>&1
    if yum -q makecache fast --disablerepo='mariadb' >/dev/null 2>&1; then
      ok "Vault repos active — yum cache rebuilt"
    else
      warn "yum still failing after repo fix — see /etc/yum.repos.d/ for other broken repos"
      warn "Try: yum-config-manager --disable <repo_name>  for any non-essential broken repo"
    fi
  else
    ok "CentOS 7 yum already functional (vault or working mirror)"
  fi
fi

FREE_DISK_MB=$(df -Pm /usr/local | awk 'NR==2{print $4}')
[ "${FREE_DISK_MB:-0}" -ge 500 ] || die "Need ≥500MB free in /usr/local (have ${FREE_DISK_MB}MB)"
RAM_MB=$(awk '/MemTotal/{printf "%d",$2/1024}' /proc/meminfo)
ok "Disk free: ${FREE_DISK_MB}MB | RAM: ${RAM_MB}MB"
SUMMARY_KV ram_mb "$RAM_MB"
SUMMARY_KV disk_free_mb "$FREE_DISK_MB"

# Already installed?
ALREADY_INSTALLED=0
if [ -d /opt/cpguard ] && command -v cpgcli >/dev/null 2>&1; then
  ALREADY_INSTALLED=1
  CUR_VER=$(cpgcli --version 2>/dev/null | head -1 || echo unknown)
  warn "cPGuard already installed ($CUR_VER) — will skip installer, refresh config + license only"
  SUMMARY_KV preexisting "yes"
else
  SUMMARY_KV preexisting "no"
fi

# cPGuard requires the OWASP-old ModSec ruleset to be the active baseline
# before install (its installer writes paths assuming it exists). If the
# server is still on Comodo WAF, abort here with clear instructions —
# rather than letting `expect` time out mysteriously mid-install.
OWASP_DIR=/usr/local/apache/modsecurity-owasp-old
if [ "$ALREADY_INSTALLED" -eq 0 ] && [ ! -d "$OWASP_DIR" ]; then
  CURRENT_WAF=""
  [ -d /usr/local/apache/modsecurity-comodo ] && CURRENT_WAF="comodo"
  [ -d /usr/local/apache/modsecurity-crs    ] && CURRENT_WAF="${CURRENT_WAF:+$CURRENT_WAF + }crs"
  [ -z "$CURRENT_WAF" ] && CURRENT_WAF="unknown/none"
  cat <<EOF | tee -a "$LOG"

================================================================
  ABORT: OWASP-old ModSec ruleset not installed on this server.

  cPGuard's installer requires $OWASP_DIR
  to exist before it will run. Current active WAF: $CURRENT_WAF

  FIX (per server, takes 30 seconds in CWP admin):
    1. Log into CWP admin
    2. Security  ->  ModSecurity
    3. Switch active ruleset to "OWASP" (or OWASP rules)
    4. Save / Install
    5. Re-run this script

  Note: OWASP is only required DURING install. Once cPGuard is up,
  the active ruleset becomes cPGuard's own — OWASP becomes inert.
================================================================
EOF
  die "Switch to OWASP in CWP first, then re-run."
fi
[ -d "$OWASP_DIR" ] && ok "OWASP-old baseline present (required by cPGuard installer)"

# CSF present?
CSF_PRESENT=0
if [ -x /usr/sbin/csf ] || [ -d /etc/csf ]; then
  CSF_PRESENT=1
  ok "CSF detected — will migrate after install"
fi
SUMMARY_KV csf_present "$CSF_PRESENT"

# Snapshot mod_security.conf before any edits
MSEC_CONF=/usr/local/apache/conf.d/mod_security.conf
if [ -f "$MSEC_CONF" ] && [ ! -f "$MSEC_CONF.bh-preinstall" ]; then
  cp -a "$MSEC_CONF" "$MSEC_CONF.bh-preinstall"
  ok "Snapshot saved: $MSEC_CONF.bh-preinstall"
fi

# ---------- 2. Whitelist cPGuard IPs ----------
log "[2/9] Whitelisting cPGuard call-home IPs..."
CPG_IPS=(137.184.200.210 159.89.87.35 167.99.149.179)
for ip in "${CPG_IPS[@]}"; do
  if command -v csf >/dev/null 2>&1; then
    grep -q "^$ip" /etc/csf/csf.allow 2>/dev/null || csf -a "$ip" "cpguard" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-source="$ip" >/dev/null 2>&1 || true
  fi
done
command -v firewall-cmd >/dev/null && firewall-cmd --reload >/dev/null 2>&1 || true
ok "Whitelisted: ${CPG_IPS[*]}"

# ---------- 3. cPGuard install (manual step) ----------
log "[3/9] Checking cPGuard install state..."

if [ "$ALREADY_INSTALLED" -eq 0 ]; then
  # cPGuard's interactive installer uses ANSI/terminal control codes that
  # don't play well with expect-driven automation (prompts get double-sent,
  # input gets rejected, etc — burned several hours on this). Easier and
  # more reliable: run the cPGuard installer MANUALLY (2 min of typing),
  # then re-run this script for the post-install patches/license/verify.
  cat <<EOF | tee -a "$LOG"

================================================================
  cPGuard is not installed. Please install it now MANUALLY, then
  re-run this script. Two commands:

  STEP A — Download + run cPGuard installer:
    cd /usr/local/src
    rm -f cpguard_install.sh
    curl -fsSL https://downloads.opsshield.com/cpguard/cpguard_install.sh -o cpguard_install.sh
    bash cpguard_install.sh ${LICENSE}

  Answer the prompts in this exact order:
    web_server               = apache
    web_server_conf          = /usr/local/apache/conf.d/vhosts/*.conf
    domain_list              = (just press Enter)
    user_list                = (just press Enter)
    Do you want suspend hook? [y/n] = n
    waf_server               = apache
    waf_server_conf          = /usr/local/apache/cpguard.conf
    webserver_restart_command = systemctl restart httpd
    waf_audit_log            = /usr/local/apache/logs/modsec_audit.log
    waf_error_log            = (just press Enter)

  Wait until you see "Installation complete".

  STEP B — Re-run THIS script (it will detect cPGuard installed and
  do all the post-install patches + license + WAF + verify):
    bash $0 ${LICENSE}
================================================================
EOF
  die "Manual cPGuard install required — see instructions above."
else
  ok "cPGuard already installed ($CUR_VER) — proceeding to post-install steps"
fi

CPG_VER=$(cpgcli --version 2>/dev/null | head -1 || echo unknown)
SUMMARY_KV cpguard_version "$CPG_VER"

# ---------- 4. Patch mod_security.conf ----------
log "[4/9] Patching $MSEC_CONF..."

if [ -f "$MSEC_CONF" ]; then
  # Comment any active owasp-old/owasp.conf Include
  sed -i -E 's|^[[:space:]]*Include[[:space:]]+"?/usr/local/apache/modsecurity-owasp-old/owasp\.conf"?|#&|' "$MSEC_CONF"

  # Ensure cpguard.conf Include is present, placed INSIDE the <IfModule
  # security2_module> block (right after the commented OWASP line) — matches
  # the BiswasHost manual procedure exactly. Falls back to end-of-file only
  # if the OWASP line isn't there (unusual config).
  if grep -qE '^[[:space:]]*Include[[:space:]]+"?/usr/local/apache/cpguard\.conf"?' "$MSEC_CONF"; then
    ok "cpguard.conf Include already present"
  elif grep -qE '^[[:space:]]*#.*modsecurity-owasp-old/owasp\.conf' "$MSEC_CONF"; then
    # Insert right after the now-commented OWASP line, preserving indentation
    sed -i '/^[[:space:]]*#.*modsecurity-owasp-old\/owasp\.conf/a\            Include "/usr/local/apache/cpguard.conf"' \
      "$MSEC_CONF"
    ok "Added cpguard.conf Include inside <IfModule> block"
  else
    # Fallback: append at end with leading newlines (covers weird configs)
    printf '\n\nInclude "/usr/local/apache/cpguard.conf"\n' >> "$MSEC_CONF"
    warn "OWASP Include line not found; appended cpguard.conf Include at end of file"
  fi
else
  warn "$MSEC_CONF missing — installer may not have created it. Skipping patch."
fi

# ---------- 5. BiswasHost cPGuard exclusions ----------
if [ "$APPLY_EXCLUSIONS" = "1" ]; then
  log "[5/9] Writing BiswasHost cPGuard exclusions..."
  mkdir -p /etc/cpguard
  cat > /etc/cpguard/custom-exclusions.conf <<'EXCL'
# BH-CPGUARD-EXCLUSIONS — managed by cpguard-install.sh, safe to edit
#
# Only cPGuard-native rule IDs belong here. OWASP/Comodo rule IDs
# (210xxx, 950xxx, 960xxx, 973xxx, 981xxx, etc.) don't exist in
# cPGuard's ruleset, so SecRuleRemoveById against them is a no-op.

# Proxy IPDB block — false-positives BD consumer ISPs on ecommerce sites
SecRuleRemoveById 1006000
# END BH-CPGUARD-EXCLUSIONS
EXCL

  # Also append rule 1006000 marker to wafurls.txt (matches manual procedure)
  if [ -f /etc/cpguard/wafurls.txt ] && ! grep -q "SecRuleRemoveById 1006000" /etc/cpguard/wafurls.txt; then
    cat >> /etc/cpguard/wafurls.txt <<'EOF'

# Disable Proxy IPDB block (rule 1006000) — false-positives BD consumer ISPs
SecRuleRemoveById 1006000
EOF
  fi
  ok "Exclusions written (1 cPGuard-native rule: 1006000)"
else
  log "[5/9] Skipped exclusions (APPLY_EXCLUSIONS=0)"
fi

# ---------- 6. CSF migration ----------
if [ "$MIGRATE_CSF" = "1" ] && [ "$CSF_PRESENT" -eq 1 ]; then
  log "[6/9] Migrating CSF rules to cPGuard..."
  if [ -f /opt/cpguard/app/scripts/csf_migration.php ]; then
    # cPGuard's migration script requires PHP >= 8.1 (Composer platform_check).
    # On older CWP boxes with PHP 7.x, it crashes — skip cleanly rather than
    # spamming useless error output.
    PHP_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null | head -1)
    PHP_MAJ=$(echo "$PHP_VER" | cut -d. -f1)
    PHP_MIN=$(echo "$PHP_VER" | cut -d. -f2)
    PHP_OK=0
    if [ "${PHP_MAJ:-0}" -ge 8 ] && [ "${PHP_MIN:-0}" -ge 1 ]; then PHP_OK=1; fi
    [ "${PHP_MAJ:-0}" -ge 9 ] && PHP_OK=1

    if [ "$PHP_OK" = "1" ]; then
      php /opt/cpguard/app/scripts/csf_migration.php 2>&1 | tee -a "$LOG" || warn "CSF migration script reported errors — review log"
      SUMMARY_KV csf_migrated "yes"
      ok "CSF rules imported"
    else
      warn "Default PHP is $PHP_VER — cPGuard csf_migration.php needs PHP >= 8.1"
      warn "Skipping auto-migration. CSF rules remain untouched in /etc/csf/"
      warn "Manual fix: run with PHP 8.1+ from CWP, e.g. /opt/alt/php81/usr/bin/php /opt/cpguard/app/scripts/csf_migration.php"
      SUMMARY_KV csf_migrated "skipped_php_version"
    fi
  else
    warn "csf_migration.php missing (cPGuard version too old?)"
    SUMMARY_KV csf_migrated "no_script"
  fi
else
  log "[6/9] CSF migration skipped (CSF_PRESENT=$CSF_PRESENT, MIGRATE_CSF=$MIGRATE_CSF)"
  SUMMARY_KV csf_migrated "skipped"
fi

# ---------- 7. License + WAF enable ----------
log "[7/9] Applying license + enabling WAF..."
cpgcli license --key "$LICENSE" 2>&1 | tee -a "$LOG" || warn "license --key returned non-zero"
sleep 2
cpgcli waf --enable 2>&1 | tee -a "$LOG" || warn "waf --enable returned non-zero"
cpgcli cleanup --enable >/dev/null 2>&1 || true
ok "License + WAF + cleanup applied"

# ---------- 8. Restart Apache ----------
log "[8/9] Restarting httpd..."
if httpd -t 2>&1 | tee -a "$LOG"; then
  systemctl restart httpd 2>&1 | tee -a "$LOG"
  sleep 2
  systemctl is-active --quiet httpd || die "httpd failed to start after restart — restore $MSEC_CONF.bh-preinstall and investigate"
  ok "httpd restarted cleanly"
else
  warn "httpd -t reported config errors — rolling back mod_security.conf"
  [ -f "$MSEC_CONF.bh-preinstall" ] && cp -a "$MSEC_CONF.bh-preinstall" "$MSEC_CONF"
  systemctl restart httpd
  die "Apache config invalid after cPGuard patches — rolled back, please investigate manually"
fi

# ---------- 9. Verify ----------
log "[9/9] Verifying installation..."

VERIFY_FAILS=0

LIC_STATUS=$(cpgcli license --status 2>/dev/null | tr -d '\r')
echo "$LIC_STATUS" | tee -a "$LOG"
if echo "$LIC_STATUS" | grep -iqE 'active|valid'; then
  ok "License: ACTIVE"
  SUMMARY_KV license_status "active"
else
  warn "License status not clearly Active — review above"
  SUMMARY_KV license_status "unclear"
  VERIFY_FAILS=$((VERIFY_FAILS+1))
fi

WAF_STATUS=$(cpgcli waf --status 2>/dev/null | tr -d '\r')
echo "$WAF_STATUS" | tee -a "$LOG"
if echo "$WAF_STATUS" | grep -iqE 'enabled|running|active'; then
  ok "WAF: ENABLED"
  SUMMARY_KV waf_status "enabled"
else
  warn "WAF status not clearly enabled — running cpgcli waf --enable again"
  cpgcli waf --enable >/dev/null 2>&1 || true
  SUMMARY_KV waf_status "retry_needed"
  VERIFY_FAILS=$((VERIFY_FAILS+1))
fi

systemctl is-active --quiet httpd    && ok "httpd: active"    || { warn "httpd inactive";    VERIFY_FAILS=$((VERIFY_FAILS+1)); }
systemctl is-active --quiet cpguard 2>/dev/null && ok "cpguard service: active" || warn "cpguard service: not present as systemd unit (some versions don't ship one)"

# 30s error_log sniff for fatal ModSec errors
log "Tailing error_log for 30s to detect fatal ModSec errors..."
FATAL=$(timeout 30 tail -F /usr/local/apache/logs/error_log 2>/dev/null | grep -m1 -iE 'modsecurity.*(fatal|error parsing)' || true)
if [ -n "$FATAL" ]; then
  warn "ModSec error detected: $FATAL"
  SUMMARY_KV modsec_errors "yes"
  VERIFY_FAILS=$((VERIFY_FAILS+1))
else
  ok "No fatal ModSec errors in last 30s"
  SUMMARY_KV modsec_errors "none"
fi

# HTTP smoke test — try multiple targets because nginx-varnish-apache stacks
# often don't bind nginx to 127.0.0.1, only the public IP. Pass if ANY target
# returns a valid HTTP code. Only fail if ALL targets fail.
SMOKE_CODE=""
SMOKE_TARGETS=("http://127.0.0.1/" "http://localhost/" "http://$(hostname)/")
for target in "${SMOKE_TARGETS[@]}"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $(hostname)" "$target" 2>/dev/null)
  if [[ "$code" =~ ^(200|301|302|403)$ ]]; then
    SMOKE_CODE="$code"
    ok "HTTP smoke test: $code (via $target)"
    break
  fi
done
if [ -n "$SMOKE_CODE" ]; then
  SUMMARY_KV http_smoke "$SMOKE_CODE"
else
  # Last resort: confirm WAF blocks via direct test attack URL
  attack_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://$(hostname)/?malware_expert_test_rule" 2>/dev/null)
  if [ "$attack_code" = "403" ]; then
    ok "HTTP smoke test: WAF actively blocking test attack (403) — pass"
    SUMMARY_KV http_smoke "waf_403"
  else
    warn "HTTP smoke test: all targets failed (127.0.0.1 + localhost + hostname). Verify manually: curl -I http://\$(hostname)/"
    SUMMARY_KV http_smoke "unreachable"
    VERIFY_FAILS=$((VERIFY_FAILS+1))
  fi
fi

log "================================================================"
if [ "$VERIFY_FAILS" -eq 0 ]; then
  log "RESULT: SUCCESS — cPGuard $CPG_VER installed cleanly on $(hostname)"
  SUMMARY_KV result "success"
  exit 0
else
  log "RESULT: PARTIAL — $VERIFY_FAILS verification check(s) failed on $(hostname). Review $LOG"
  SUMMARY_KV result "partial"
  exit 2
fi
