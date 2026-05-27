# Reproducing the detection stack on a fresh Ubuntu 24.04 LTS

This guide rebuilds the **endpoint + network detection** half of the SOC on a clean
**Ubuntu 24.04 LTS (Noble)** host, by hand. It is the manual translation of the
tested Ansible roles that automate the same work on the core server.

**Scope.** This covers what runs **on the monitored core host**: the Wazuh *agent*,
Suricata IDS, the auditd ruleset that feeds it, fail2ban, and the local Ollama
runtime used by the overnight triage agent. The **Wazuh manager stack**
(indexer + manager + dashboard) runs on a *separate dedicated VM* and is summarised
in the repo README ("Set up"); standing up the manager itself is out of scope here.

**Source roles** (from the private rebuild playbook, `roles/<name>`):
`wazuh-agent`, `suricata`, `auditd`, `fail2ban`, `ollama`. Custom detection content
is `rules/local_rules.xml` in this repo.

> **Conventions.** Real values are abstracted to match the repo gate: the SIEM/
> manager VM is `<MANAGER_HOST>` (substitute its address), the SSH port is
> `<SSH_PORT>`, the sniffing NIC is `<MONITOR_IFACE>` (e.g. `eth0`), the agent
> version is `<WAZUH_VERSION>`. Root-only verification commands are marked
> `# verify with: sudo ...` and were **not** executed.

---

## Contents

- [0. Prerequisites](#0-prerequisites)
- [1. auditd - kernel audit ruleset (`auditd` role)](#1-auditd---kernel-audit-ruleset-auditd-role)
- [2. Suricata - network IDS (`suricata` role)](#2-suricata---network-ids-suricata-role)
- [3. fail2ban - brute-force banning (`fail2ban` role)](#3-fail2ban---brute-force-banning-fail2ban-role)
- [4. Wazuh agent - ship everything to the SIEM (`wazuh-agent` role)](#4-wazuh-agent---ship-everything-to-the-siem-wazuh-agent-role)
  - [Custom detection rules (on the MANAGER, not this host)](#custom-detection-rules-on-the-manager-not-this-host)
- [5. Ollama - local LLM runtime for the overnight triage agent (`ollama` role)](#5-ollama---local-llm-runtime-for-the-overnight-triage-agent-ollama-role)
- [6. The Wazuh manager / application (separate host) + PKI](#6-the-wazuh-manager--application-separate-host--pki)
- [7. Automated reporting pipeline (scripts + cron)](#7-automated-reporting-pipeline-scripts--cron)
- [Order of operations (summary)](#order-of-operations-summary)

---

## 0. Prerequisites

- A fresh Ubuntu 24.04 LTS host with a `sudo`-capable user.
- The Wazuh **manager** is already reachable on the network (it issues agent
  enrollment on TCP 1515 and receives events on TCP 1514).
- Network reachability from this host to the manager on TCP `1514`, `1515`, `9200`
  (the host firewall opens these as egress; see the `homelab-network` repo's UFW
  guide).

Add the Wazuh and Suricata package sources, then refresh apt:

```bash
# Wazuh apt repo (signed)
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /etc/apt/keyrings/wazuh.asc
echo "deb [signed-by=/etc/apt/keyrings/wazuh.asc] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh-agent.list

# Suricata stable PPA
sudo add-apt-repository -y ppa:oisf/suricata-stable

sudo apt update
```

---

## 1. auditd - kernel audit ruleset (`auditd` role)

auditd produces the host's syscall/file-watch audit trail; the Wazuh agent then
ships `/var/log/audit/audit.log` to the manager. Install it and drop in the rule
set:

```bash
sudo apt install -y auditd audispd-plugins
```

The rules are split into numbered files in `/etc/audit/rules.d/`. The base file
`audit.rules` sets buffers and failure mode:

```
## First rule - delete all
-D

## Increase the buffers to survive stress events.
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1
```

Then the playbook ships a STIG-aligned, topic-split rule set (login UID immutability,
privileged-command auditing, power-abuse, container, code-injection, kernel module
load, installer, and networking watches). Copy each `*.rules` file into
`/etc/audit/rules.d/` (mode `0640`). A few watched directories must exist first:

```bash
sudo mkdir -p /etc/NetworkManager /etc/apparmor /etc/apparmor.d
# copy the numbered rule files (11-loginuid, 30-stig, 31-privileged, 32-power-abuse,
# 40-local, 41-containers, 42-injection, 43-module-load, 44-installers, 71-networking)
# into /etc/audit/rules.d/
sudo augenrules --load
sudo systemctl enable --now auditd
```

**Verify:**

```bash
# verify with: sudo auditctl -l        (lists loaded rules)
# verify with: sudo auditctl -s        (status; failure mode = 1)
```

---

## 2. Suricata - network IDS (`suricata` role)

Suricata sniffs the LAN interface and writes `eve.json`, which the Wazuh agent
ingests so network detections land beside host detections.

```bash
sudo apt install -y suricata
```

Set the AF-PACKET BPF filter on the monitored interface. The lab drops some
link-local L2 chatter (LLDP/LACP/STP) so it does not pollute alerts. Edit
`/etc/suricata/suricata.yaml`, find the `af-packet` block for your interface, and
add a `bpf-filter` line:

```yaml
af-packet:
  - interface: <MONITOR_IFACE>
    bpf-filter: "not (ether proto 0x88cc or ether proto 0x8899 or ether dst 01:80:c2:00:00:00)"
```

Pull the rule sources and validate the config before starting:

```bash
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml          # config test
sudo systemctl enable --now suricata
```

> If you see kernel packet drops under load, raise the AF-PACKET `ring-size` past the
> default (noted in the repo README).

**Verify:**

```bash
# verify with: sudo suricata -T -c /etc/suricata/suricata.yaml   (Configuration provided was successfully loaded)
ls -l /var/log/suricata/eve.json     # expect a growing JSON event log
```

---

## 3. fail2ban - brute-force banning (`fail2ban` role)

fail2ban watches auth/web/IDS logs and bans offenders via nftables. Install and
deploy `jail.local`:

```bash
sudo apt install -y fail2ban
```

`/etc/fail2ban/jail.local` (substitute `<SSH_PORT>` and your preferred ban policy):

```ini
[DEFAULT]
bantime  = <BANTIME>          # the lab uses a long persistent ban
findtime = <FINDTIME>
maxretry = <MAXRETRY>
banaction = nftables
banaction_allports = nftables[type=allports]
backend = systemd
bantime.persistence = true

[sshd]
port     = <SSH_PORT>
enabled  = true
maxretry = 3
bantime  = <BANTIME>

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2

[suricata]
enabled  = true
logpath  = /var/log/suricata/eve.json
backend  = auto
bantime  = <BANTIME>
maxretry = 3
banaction = nftables[type=allports]
```

```bash
sudo systemctl enable --now fail2ban
```

**Verify:**

```bash
# verify with: sudo fail2ban-client status          (lists active jails)
# verify with: sudo fail2ban-client status sshd      (per-jail detail)
```

---

## 4. Wazuh agent - ship everything to the SIEM (`wazuh-agent` role)

The agent collects host telemetry (auth, FIM, syscollector, SCA, journald) plus the
auditd and Suricata logs configured above, and forwards it to the manager.

Install the agent, pointing it at the manager. The `WAZUH_MANAGER` env var bakes the
manager address into the install:

```bash
sudo WAZUH_MANAGER="<MANAGER_HOST>" apt install -y wazuh-agent=<WAZUH_VERSION>
```

Deploy `/var/ossec/etc/ossec.conf` (owner `root:wazuh`, mode `0640`). Key blocks
translated from the role template:

- **client / enrollment** - manager `<MANAGER_HOST>`, port `1514/tcp`, AES crypto,
  auto-enroll with an `<AGENT_NAME>` into the `default` group.
- **syscollector** - hardware/OS/network/packages/ports/processes inventory hourly
  (this feeds the CVE pipeline the README describes).
- **sca** - Security Configuration Assessment every 12h.
- **syscheck (FIM)** - whodata-mode watches on `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot`,
  with the standard noise ignores.
- **rootcheck** - rootkit/anomaly scan, ignoring container layer dirs.
- **localfile collectors** - `auth.log`, nginx access/error, `journald`,
  `audit.log`, `dpkg.log`, periodic `df -P` / `netstat` / `last`, and crucially
  the Suricata JSON: `/var/log/suricata/eve.json` (`log_format json`).

The full file is in the role (`roles/wazuh-agent/templates/ossec.conf.j2`). The
Suricata ingestion line is the bridge between sections 2 and 4:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Enable and start:

```bash
sudo systemctl enable --now wazuh-agent
```

**Verify:**

```bash
# verify with: sudo /var/ossec/bin/agent_control -i <AGENT_ID>   (on the manager: agent Active)
# verify with: sudo tail /var/ossec/logs/ossec.log               (look for "Connected to the server")
```

### Custom detection rules (on the MANAGER, not this host)

The detection content lives on the **manager**: copy this repo's
[`rules/local_rules.xml`](../rules/local_rules.xml) to
`/var/ossec/etc/rules/local_rules.xml` and restart the manager. It implements the
three-tier model (baseline level 3 / suppressions level 0 / detections level 7-12)
and the CVE-noise tuning. Per-host suppressions must be scoped with
`win.system.computer` (the OS hostname), **not** `agent.name` (see README Gotchas).

---

## 5. Ollama - local LLM runtime for the overnight triage agent (`ollama` role)

The overnight SOC triage agent (the external `agentic-soc-triage` project) runs its
model locally via Ollama on the core host, so alert data is never sent to a
third-party API. This role installs the runtime only; the agent and its model are
configured separately.

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
```

Then pull whichever model the triage agent expects (e.g. a small local model);
that pull is part of the agent's own setup, not this role.

**Verify:**

```bash
# verify with: sudo systemctl status ollama
ollama list           # lists installed models (empty until you pull one)
curl -s http://localhost:11434/api/tags     # Ollama API responds
```

---

## 6. The Wazuh manager / application (separate host) + PKI

The agent in section 4 is only half the picture - it ships to a **manager**, which in
this lab is a dedicated host (a VM on the core server), not this box. You download and
run the **Wazuh central components** there: `wazuh-indexer` (stores + searches alerts),
`wazuh-manager` (analysis engine + rules), and `wazuh-dashboard` (the UI).

Two official ways to stand it up - this lab uses the OVA:

```bash
# Option A - the all-in-one installation assistant on a fresh host
curl -sO https://packages.wazuh.com/<WAZUH_BRANCH>/wazuh-install.sh
sudo bash wazuh-install.sh -a        # -a = all-in-one: indexer + manager + dashboard
# prints the generated admin dashboard credentials at the end

# Option B - import the prebuilt Wazuh OVA into the hypervisor (what this lab does),
# give it a static address, then boot. Same three components, pre-assembled.
```

**PKI is generated here, and it is not optional** - the components and agents talk over
TLS, so the install creates a small CA and per-component certs:

- `wazuh-certs-tool.sh` (driven by `config.yml`) emits a **root CA** plus **indexer**,
  **filebeat/manager**, and **dashboard** certificates.
- The agent **enrolls** against the manager over `1515/tcp`, then streams events over
  `1514/tcp` - the `WAZUH_MANAGER` value from section 4 must point at this host.
- Keep the generated `wazuh-certificates.tar` in the backup set: a rebuild **restores**
  it rather than regenerating, so existing agents keep trusting the manager.

Pin the manager to the same `<WAZUH_VERSION>` as the agent so they match.

```bash
# verify with: curl -k https://<MANAGER_HOST>:9200          (indexer answers over TLS)
# verify with: the dashboard at https://<MANAGER_HOST> lists this host's agent as Active
```

Once it is up, deploy the detection content (`rules/local_rules.xml`, section 4) and
wire the real-time level-7+ alert integration to a chat bot.

---

## 7. Automated reporting pipeline (scripts + cron)

Detection only pays off if someone reads it - so the read is automated. A nightly job
pulls the day's signals, the local LLM (section 5) triages them, and a dated report is
written. It all runs on the core host as plain scripts under cron.

**Extra packages/access the reporting needs**, beyond the detection stack:

```bash
sudo apt install -y jq curl netcat-openbsd
# plus: an SSH key trusted by the edge router (to pull its logs),
#       and read access to the Wazuh indexer API at https://<MANAGER_HOST>:9200
```

**The scripts:**

| Script | When | What it does |
|---|---|---|
| `generate-security-report.sh` | cron, daily `0 4 * * *` | Queries the Wazuh indexer API (`curl` + `jq`), pulls the edge router's logs over `ssh`, probes listening services with `nc`, and writes a dated markdown report. |
| `soc-agent.sh` | called by the report | The L1 triage: feeds each finding to the local Gemma model via Ollama (section 5), classifies KNOWN / SUSPICIOUS / UNKNOWN, drafts the summary, keeps a self-updating correlation memory, and escalates only what it cannot resolve to an L2 (human / Claude) review. |
| `generate-monthly-report.sh` | cron, monthly `0 6 1 * *` | Rolls the dailies into a monthly baseline. |
| `sec-note` | manual, before maintenance | Pre-annotates planned events so they land in the report as expected, not as anomalies. |

Wire the cron:

```bash
crontab -e
# 0 4 * * *   /path/to/generate-security-report.sh >> ~/.local/log/security-report-cron.log 2>&1
# 0 6 1 * *   /path/to/generate-monthly-report.sh   >> ~/.local/log/security-report-cron.log 2>&1
```

```bash
# verify with: run generate-security-report.sh by hand once; confirm a dated report is written
# verify with: tail ~/.local/log/soc-agent.log    (Stage 1 -> Stage 2 -> Stage 3 of the overnight run)
```

The scripts live with the operator's notes rather than in this repo; this section
documents the pipeline so it can be rebuilt. Treat the indexer credentials and the
router SSH key as part of the backup set.

---

## Order of operations (summary)

The playbook sequences the host detection stack as:

1. `fail2ban` - installed early (package set), jail config here.
2. `suricata` - sniff + eve.json (must exist before the agent ingests it).
3. `auditd` - audit trail (must exist before the agent ships audit.log).
4. `wazuh-agent` - ties it all together and ships to the manager.
5. `ollama` - local runtime for the overnight triage agent (independent).

Plus, on the **separate manager VM**: install `wazuh-indexer` -> `wazuh-manager`
-> `wazuh-dashboard` (start in that order), then deploy `local_rules.xml` and wire
the level-7+ real-time alert integration. See the repo README "Set up".

A working detection node = agent shows **Active** on the manager, Suricata writing
`eve.json`, auditd loaded, fail2ban jails active, and Ollama answering on
`localhost:11434`.
