# Aegis 

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Category-Web%20Security-red?style=for-the-badge&logo=target" alt="Category" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status" />
  <img src="https://img.shields.io/badge/Contributions-Welcome-orange?style=for-the-badge" alt="PRs Welcome" />
</p>

<p align="center">
  <strong> A very fast, lightweight web directory fuzzer and DNS subdomain enumerator engineered for beginners who want to learn the basics of web reconnaissance. </strong>
</p>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#architecture--performance">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#command-line-reference">Command Reference</a> •
  <a href="#practical-examples">Examples</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

---

<img width="1097" height="780" alt="aegis-sample" src="https://github.com/user-attachments/assets/d1fa457b-0a33-4750-9c66-3f09c067beac" />


---

##  Key Features

- **Dual Discovery**: fast HTTP endpoint fuzzing (`dir`) and high-speed DNS A-record brute-forcing (`sub`).
- **Low-Overhead HTTP Fuzzing**: Automatically probes targets with lightweight HTTP `HEAD` requests to minimize payload transfer, transparently degrading to streamed `GET` requests only when encountering `405 Method Not Allowed`.
- **Dynamic Connection Pooling**: Optimized socket reuse across threads with explicit response stream termination to prevent file descriptor leaks.
- **Granular Status Code Filtering**: Target-specific status filtering (200 OK, 30x Redirects, 403 Forbidden).

---


##  Installation

```bash
# Clone the repository
git clone https://github.com/no-samsepi0l/Aegis.git
cd aegis

# Set up a python environment (Recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
# for fish terminal user:
source venv/bin/activate.fish

# Install required packages
pip install -r requirements.txt
```

### Global Installation (Optional)
To use `aegis` as a system-wide command from any folder:

```bash
chmod +x aegis.py
sudo ln -s $(pwd)/aegis.py /usr/local/bin/aegis
```

---

##  Command-Line Reference

```text
usage: aegis.py [-h] [-m {dir,sub}] -u URL -w WORDLIST [-t TIMEOUT] [-T THREADS]
                [-mc MATCH_CODES] [-x EXTENSIONS]
```

| Flag | Long Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-m` | `--mode` | `str` | `dir` | Scan mode: `dir` (directory discovery) or `sub` (subdomain DNS lookup). |
| `-u` | `--url` | `str` | **Required** | Target URL (e.g., `https://target.com/`) or root domain (e.g., `target.com`). |
| `-w` | `--wordlist` | `str` | **Required** | Absolute or relative path to the dictionary/wordlist file. |
| `-t` | `--timeout` | `float`| `1.5` | Network socket timeout in seconds per individual probe. |
| `-T` | `--threads` | `int` | `20` | Maximum number of concurrent worker threads. |
| `-mc`| `--match-codes`| `str` | `200,301,302,308,403` | Comma-delimited list of HTTP status codes to flag and print. |
| `-x` | `--extensions` | `str` | `None` | Comma-separated file extensions to append to each wordlist item (e.g., `php,html,txt`). |
| `-h` | `--help` | - | - | Show the help message and exit. |

---

##  Practical Examples

### 1. Standard Web Discovery
Scan standard routes using a standard directory wordlist:
```bash
python aegis.py -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt    # normal path in Kali
```

### 2. High-Speed API & Hidden File Enumeration
Scan with 60 threads, shorter timeout, and automatic extension appending:
```bash
python aegis.py -u https://example.com -w wordlists/endpoints.txt -T 60 -t 1.0 -x json,env,bak,php
```

### 3. Strict Status Code Isolation
Only display valid responses (`200 OK`) and access-controlled endpoints (`403 Forbidden`):
```bash
python aegis.py -u https://example.com -w wordlists/raft-medium-directories.txt -mc 200,403
```

### 4. Fast Subdomain Resolution
Perform DNS resolution on a root domain using redundant external resolvers (Cloudflare `1.1.1.1` & Google `8.8.8.8`):
```bash
python aegis.py -m sub -u example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -T 40
```

---

##  Terminal Output Preview

```text
Starting Aegis....
===================================
Welcome to Aegis, a web enumeration tool designed to help security professionals and students discover hidden directories
------------------------------------------------------------------------------------------------------------------------------------------------------
Please, this tool is for educational purpose only. Use it responsibly and ethically. I am not responsible for any misuse of this tool.

[=====================================]
[*] Target: [https://target.local/](https://target.local/)
[*] Mode: DIR
[*] Wordlist: common.txt
[*] Timeout: 1.0s
[*] Threads: 50
[*] Match-codes: [200, 301, 302, 308, 403]
[*] Extensions: ['php', 'env']
==================================================
STARTING THE SCAN WITH: [https://target.local/](https://target.local/)
==================================================
[+] Found: /.git/index               | Status: 308 [--> /.git/]
[+] Found: /.env                     | Status: 200
[+] Found: /admin                    | Status: 403
[+] Found: /api/v1/health            | Status: 200
[+] Found: /index.php                | Status: 200
[+] Scanning: 100%|###########################| 4752/4752 [00:06<00:00, 725.10req/s]

[--------------------------------------------------]
[===========]
 Finished!
[===========]

[+] Aegis has completed the scan !
[+] Total Found: 5
[+] Aegis has completed the scan in 6.55 seconds. Exiting...
```

---

##  Roadmap

- [ ] **Structured Output**: Export results directly to JSON, CSV, or formatted Markdown reports (`-o / --output`).
- [ ] **Proxy Integration**: Full upstream HTTP/HTTPS and SOCKS5 proxy routing (`--proxy`).
- [ ] **Recursive Discovery**: Automated secondary fuzzing pass on discovered folders.
- [ ] **Response Filtering**: Filter out false-positives using response body length (`--filter-size`) and regex pattern matching.
- [ ] **Rate Limiting**: Configurable maximum requests per second (RPS) to evade anti-automation blocks.

---

## note

I was thinking about integrating an automated scan review system with AI, using OpenRouter or NVIDIA NIM.

---
