# CentOS 7 Repo Fix — EOL Mirror Workaround

**Use this on any CentOS 7 server where `yum` is returning HTTP 404 on package downloads.**

## Why this happens

CentOS 7 reached **end-of-life on 2024-06-30**. Red Hat / CentOS pulled it from the active mirror network. The standard mirror.centos.org (and downstream providers like mirror.leaseweb.com) no longer serve CentOS 7 packages — every `yum install` / `yum update` gets `HTTP 404 - Not Found`.

The packages still exist, just at different URLs:

| Repo | Old (dead) | New (archive) |
|---|---|---|
| CentOS Base / Updates / Extras | mirror.centos.org, leaseweb, etc. | **vault.centos.org** |
| EPEL 7 | download.fedoraproject.org | **archives.fedoraproject.org/pub/archive** |
| MariaDB 10.x for CentOS 7 | yum.mariadb.org | **archive.mariadb.org** |

## The Fix (4 steps, ~2 minutes)

### Step 1 — Replace CentOS-Base.repo

```bash
cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak

cat > /etc/yum.repos.d/CentOS-Base.repo <<'EOF'
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
EOF
```

### Step 2 — Replace epel.repo (if EPEL is installed)

```bash
[ -f /etc/yum.repos.d/epel.repo ] && cp /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.bak

cat > /etc/yum.repos.d/epel.repo <<'EOF'
[epel]
name=Extra Packages for Enterprise Linux 7 - $basearch
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
EOF
```

### Step 3 — Point MariaDB repo at archive (if MariaDB repo is configured)

```bash
if [ -f /etc/yum.repos.d/mariadb.repo ]; then
  cp /etc/yum.repos.d/mariadb.repo /etc/yum.repos.d/mariadb.repo.bak
  sed -i 's|http://yum.mariadb.org/10.4/centos7-amd64|https://archive.mariadb.org/mariadb-10.4/yum/centos7-amd64|g' \
    /etc/yum.repos.d/mariadb.repo
  # If client runs a different MariaDB version, adjust 10.4 to match
  # (10.3, 10.5, 10.6, 10.11 also have archive paths)
fi
```

### Step 4 — Rebuild yum cache + test

```bash
yum clean all
yum makecache fast
yum install -y expect    # smoke test — should succeed cleanly now
```

If `yum install -y expect` succeeds without 404s, the server is fixed. You can now run `yum update -y` for security backports OR proceed with the cPGuard installer.

## Other repos you might encounter on CWP CentOS 7

These are usually still OK because they're third-party and aren't tied to CentOS's mirror network:

- `nginx.repo` — nginx.org still serves CentOS 7
- `remi*.repo` — Remi's PHP repos still serve CentOS 7
- `cwp.repo` — Control Web Panel still serves CentOS 7
- `varnishcache_*` — Packagecloud still works

If any of these break later, the same pattern applies: find the vendor's archive URL and update the `baseurl=` line.

## When to skip a repo instead of fixing it

For one-off tasks (like installing cPGuard) where you don't actually need the broken repo's packages:

```bash
yum-config-manager --disable <repo_name>
```

Example — skip MariaDB repo when you only need `expect`:
```bash
yum-config-manager --disable mariadb
yum install -y expect
yum-config-manager --enable mariadb   # re-enable after, if you want
```

## Verify the fix held

After running `yum update -y` you should see packages actually download from vault.centos.org, e.g.:

```
http://vault.centos.org/7.9.2009/updates/x86_64/Packages/bind-9.11.4-26.P2.el7_9.16.x86_64.rpm  | 2.3 MB  00:00:01
```

## Strongly recommend to client

CentOS 7 is **past end-of-life**. No more upstream CVE patches from Red Hat. Vault gives you the final frozen package set as of June 2024 — nothing newer. Recommend migration to **AlmaLinux 9** (the official drop-in CentOS replacement) within 3-6 months. AlmaLinux is binary-compatible with RHEL 9, free, and CWP supports it.

In your Fiverr delivery message you can phrase it like:

> *"Note: this server is on CentOS 7, which Red Hat retired in June 2024. cPGuard's WAF gives strong application-layer protection, but kernel-level CVE patches stopped coming. I'd strongly recommend migrating to AlmaLinux 9 within the next 3-6 months. Happy to quote that migration separately if you'd like."*
