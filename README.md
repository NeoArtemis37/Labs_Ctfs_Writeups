# Cybersecurity Lab & CTF Writeups

This repository serves as a centralized archive for technical reports (writeups), vulnerability analyses, and exploitation methodologies developed during the resolution of cybersecurity laboratories (such as Hack The Box, TryHackMe, Root-Me) and Capture The Flag (CTF) competitions.

The primary objective of this project is to document complex attack chains (Kill Chains) encountered, consolidate penetration testing methodologies, and provide detailed remediation strategies (Blue Teaming) for each scenario.

---

## Repository Structure

The project directory is structured by platform and technical category to ensure straightforward navigation:

```text
.
├── ctf/                    # Chronological CTF competition writeups
│   └── 2026-ETSCTF/        # Challenge-specific artifacts and reports
│       └── privesc-semver/ # Documentation regarding semver-tags exploitation
├── labs/                   # Continuous training laboratory environments
│   ├── hackthebox/         # Hack The Box machine writeups
│   └── tryhackme/          # TryHackMe room documentation
├── methodologies/          # Technical summaries, checklists, and cheatsheets
└── README.md               # Main repository index
```

---

## Technical Domain Focus

The analyses documented within this repository encompass the following core domains:

- **Web Security & RCE:** Exploitation of application business logic, insecure deserialization flaws (CWE-502), code execution, and OS command injections (CWE-78).
- **Linux Privilege Escalation:** Auditing permissive sudoers configurations, misconfigured SUID binaries, exploitation of internal maintenance scripts, and vulnerable third-party dependencies.
- **Vulnerability Analysis (CVE):** Evaluating the real-world impact of newly disclosed vulnerabilities or third-party advisory reports (e.g., Snyk, MITRE).
- **Remediation & Defenses (Blue Teaming):** Authoring formal security recommendations, hardening system configurations (Sudoers policies, file system permissions), and implementing secure coding practices.

---

## Standard Report Methodology

To guarantee clarity, peer review efficiency, and reproducibility, every writeup follows a rigorous, standard template:

1. **General Information:** Identification of the target environment, initial user footprint, and referenced CVEs or vulnerability identifiers.
2. **Reconnaissance & Enumeration:** Documentation of network-level footprinting, application fuzzing, and local enumeration phases (e.g., open ports, automated scan outputs, configuration audits).
3. **Exploitation Chain (Kill Chain):** Step-by-step description of the execution path leading to system compromise, featuring exact syntax inputs and error log analysis.
4. **Remediation Report:** Defensive assessment detailing structural engineering fixes (e.g., library updates, source code rewrites, enforcement of the principle of least privilege).

---

## Legal Disclaimer

All content hosted in this repository is strictly intended for educational purposes, security research, and academic skill validation. The utilization of these techniques against unauthorized third-party systems without prior explicit consent is illegal. The author assumes no liability for the misuse or misinterpretation of the methodologies documented herein.
