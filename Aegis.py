import argparse
import warnings
import time
import os
import requests
import dns.resolver
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from tqdm import tqdm

#warnings.filterwarnings("ignore", category=UserWarning, module="requests")
init(autoreset=True)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Aegis - High-Performance Web Enumeration Tool")
    parser.add_argument("-m", "--mode", choices=["dir", "sub"], default="dir",
                        help="scan mode: 'dir' for directory fuzzing or 'sub' for subdomain enumeration (default: dir)")
    parser.add_argument("-u", "--url", required=True, help="Full URL or Domain of the target (e.g., http://example.com/)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Timeout in seconds (default: 1.5)")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("-mc", "--match-codes", type=str, default="200,301,302,308,403", 
                        help="HTTP status codes to show (default: 200,301,302,308,403)")
    parser.add_argument("-x", "--extensions", type=str, default="", 
                        help="File extensions to append (e.g., php,html,txt)")

    # AI Options
    parser.add_argument("--ai", action="store_true", help="Enable AI analysis of suspicious findings after scan")
    parser.add_argument("--api-key", type=str, 
                        default=os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("NVIDIA_API_KEY"), 
                        help="API key for AI provider")
    parser.add_argument("--api-url", type=str, default="https://integrate.api.nvidia.com/v1/chat/completions",
                        help="API endpoint URL")
    parser.add_argument("--model", type=str, default="moonshotai/kimi-k2.6",
                        help="AI model name")
    return parser.parse_args()


def print_banner():
    print(Fore.GREEN + "Starting Aegis....")
    print("=" * 35)
    print(Fore.GREEN + Style.BRIGHT + "Welcome to Aegis, a web enumeration tool designed to help security professionals and students discover hidden directories")
    print("-" * 150)
    print("Please, this tool is for educational purpose only. Use it responsibly and ethically. I am not responsible for any misuse of this tool.")

    print(Fore.GREEN + "\n" + "[=" + "=" * 35 + "=]")
    print(Fore.RED + Style.BRIGHT + """  
  ▄▄▄      ▓█████   ▄████  ██▓  ██████ 
 ▒████▄    ▓█   ▀  ██▒ ▀█▒▓██▒▒██    ▒ 
 ▒██  ▀█▄  ▒███   ▒██░▄▄▄░▒██▒░ ▓██▄   
 ░██▄▄▄▄██ ▒▓█  ▄ ░▓█  ██▓░██░  ▒   ██▒
 ▓█   ▓██▒░▒████▒░▒▓███▀▒░██░▒██████▒▒
 ▒▒   ▓▒█░░░ ▒░ ░ ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░
 ▒   ▒▒ ░ ░ ░  ░  ░   ░  ▒ ░░ ░▒  ░ ░
 ░   ▒      ░   ░ ░   ░  ▒ ░░  ░  ░  
 ░  ░   ░  ░      ░  ░        ░
 
 made by: @no-samsepi0l""")
    print(Fore.GREEN + "[=" + "=" * 35 + "=]")  


def check_path(session, url, path, timeout, match_codes, results):
    target_url = f"{url}{path}"
    try:
        response = session.head(target_url, timeout=timeout, allow_redirects=False)

        if response.status_code == 405:
            
            response.close()
            response = session.get(target_url, timeout=timeout, allow_redirects=False, stream=True)

        if response.status_code in match_codes:
            if response.status_code == 200:
                color = Fore.GREEN
            elif response.status_code in [301, 302, 308]:
                color = Fore.CYAN
            elif response.status_code == 403:
                color = Fore.YELLOW
            else:
                color = Fore.WHITE

            redirected_url = ""
            if response.status_code in [301, 302, 308] and "Location" in response.headers:
                redirected_url = f" [--> {response.headers['Location']}]"

            formatted_res = f"{color}[+] Found: /{path:<25} | Status: {response.status_code}{redirected_url}"
            tqdm.write(formatted_res)
            results.append(formatted_res)

        
        response.close()
    except requests.RequestException:
        pass


def check_subdomain_dns(domain, sub, timeout, resolver, results):
    target_fqdn = f"{sub}.{domain}"

    try: 
        answers = resolver.resolve(target_fqdn, "A", lifetime=timeout)
        ips = [str(rdata) for rdata in answers]
        if ips:
            ip_str = ", ".join(ips)
            formatted_res = f"{Fore.GREEN}[+] Subdomain found: {target_fqdn:<35} | IP: {ip_str}"
            tqdm.write(formatted_res)
            results.append(formatted_res)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
        pass


def analyze_findings_ai(results, target, api_key, api_url, model):
    if not api_key:
        print(Fore.RED + "\n[-] AI Error: No API key provided.")
        return

    #You can add interesting_keywords but if you do, make sure to change interesting_findings to filter based on those keywords.    
    interesting_findings = results[:15]

    findings_text = "\n".join(interesting_findings)

    prompt = f"""
You are a senior cybersecurity expert and penetration testing consultant.
Below are key findings from a web enumeration scan against target '{target}':

{findings_text}

Provide a concise, high-impact security analysis:
1. **Critical Resources Discovered** (e.g., exposed secrets, admin interface exposures, sensitive backups, .git leaks).
2. **Priority Attack Vectors** to investigate first based on these findings.
3. **Recommended Exploitation & Enumeration Tools** (mention modern tools like GitTools, Nuclei, ffuf, SQLmap, Nmap, etc.).
4. **Concrete Remediation & Hardening Steps** for the system administrator.

Keep your tone professional, direct, structured, and strictly technical.(but give your response under 60 seconds)
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/aegis-scanner",
        "X-Title": "Aegis Scanner"
    }

    candidate_models = [
        model,
        "deepseek-ai/deepseek-v4.1-flash",
        "google/gemma-2b",
        "deepseek-ai/deepseek-v4-flash-0731",#this list needs to be updated with the latest models available on the NVIDIA API or OpenRouter API and must be available with your plan.
        "meta/llama-3.2-11b-vision-instruct"
    ]

    candidate_models = list(dict.fromkeys(candidate_models))

    for current_model in candidate_models:
        print(Fore.MAGENTA + f"\n[*] Trying AI analysis with model: {current_model}...")
        payload = {
            "model": current_model,
            "messages": [
                {"role": "system", "content": "You are a world-class cybersecurity expert and penetration testing assistant."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3
        }

        try:
            response = requests.post(api_url, json=payload, headers=headers, timeout=60)
            if response.status_code == 200:
                ai_response = response.json()["choices"][0]["message"]["content"]
                print(Fore.MAGENTA + "\n" + "=" * 55)
                print(Fore.MAGENTA + Style.BRIGHT + "🤖 AI ANALYSIS & RECOMMENDATIONS")
                print(Fore.MAGENTA + "=" * 55)
                print(Fore.WHITE + ai_response)
                print(Fore.MAGENTA + "=" * 55)
                return
            else:
                print(Fore.YELLOW + f"[!] Model '{current_model}' failed (Status {response.status_code}). Trying fallback...")
        except Exception as e:
            print(Fore.YELLOW + f"[!] Request error with '{current_model}': {e}")

    print(Fore.RED + "\n[-] All NVIDIA candidate models failed. Switched to OpenRouter API automatically...")

    try:
        openrouter_headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        openrouter_payload = {
            "model": "meta-llama/llama-3.3-70b-instruct:free",
            "messages": [
                {"role": "system", "content": "You are a world-class cybersecurity expert."},
                {"role": "user", "content": prompt}
            ]
        }
        res = requests.post("https://openrouter.ai/api/v1/chat/completions", json=openrouter_payload, headers=openrouter_headers, timeout=30.0)
        if res.status_code == 200:
            print(Fore.MAGENTA + "\n" + "=" * 55)
            print(Fore.MAGENTA + Style.BRIGHT + "🤖 AI ANALYSIS & RECOMMENDATIONS (OpenRouter)")
            print(Fore.MAGENTA + "=" * 55)
            print(Fore.WHITE + res.json()["choices"][0]["message"]["content"])
            print(Fore.MAGENTA + "=" * 55)
        else:
            print(Fore.RED + "[-] Final fallback failed. Check your API Key or Network.")
    except Exception as ex:
        print(Fore.RED + f"[-] Final fallback error: {ex}")


def web_enumeration(mode, target_input, wordlist_path, timeout, threads, match_codes_str, extensions_str, ai_enabled, api_key, api_url, model):
    domain = ""
    url = ""

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']

    if mode == "dir":
        url = target_input
        if not url.startswith(("http://", "https://")):
            print(Fore.RED + "[-] Error: For 'dir' mode, url must start with 'http://', or 'https://'")
            return None, 0
        if not url.endswith("/"):
            url += '/'
    else:
        clean_input = target_input.replace("http://", "").replace("https://", "").strip("/")
        domain = clean_input.split(":")[0]

    try:
        valid_code = {int(code.strip()) for code in match_codes_str.split(",") if code.strip()}
    except ValueError:
        print(Fore.RED + "[-] Error: --match-codes must be numbers separated by commas (e.g. 200,301,403)")
        return None, 0

    extensions = [ext.strip().lstrip(".") for ext in extensions_str.split(",") if ext.strip()]

    if mode == "dir":
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(":")[0]

    print(Fore.CYAN + f"[*] Target: {url if mode == 'dir' else domain}")
    print(Fore.CYAN + f"[*] Mode: {mode.upper()}")
    if mode == "sub":
        print(Fore.CYAN + f"[*] Base domain: {domain}")
    print(Fore.CYAN + f"[*] Wordlist: {wordlist_path}")
    print(Fore.CYAN + f"[*] Timeout: {timeout}s")
    print(Fore.CYAN + f"[*] Threads: {threads}")
    print(Fore.CYAN + f"[*] Match-codes: {sorted(list(valid_code))}")
    if mode == "dir":
        print(Fore.CYAN + f"[*] Extensions: {extensions if extensions else 'None'}")
    if ai_enabled:
        print(Fore.MAGENTA + f"[*] AI Analysis: ENABLED")
    print("=" * 50)
    print(f"STARTING THE SCAN WITH: {url if mode == 'dir' else domain}")
    print("=" * 50)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    })

    paths = []
    try:
        with open(wordlist_path, "r", encoding='utf-8', errors='ignore') as file:
            for line in file:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue

                paths.append(word)
                if mode == "dir":
                    for ext in extensions:
                        paths.append(f"{word}.{ext}")

    except FileNotFoundError:
        print(Fore.RED + f"[-] Error: Wordlist file '{wordlist_path}' not found.")
        return None, 0

    total_tasks = len(paths)
    results = []
    start_time = time.time()

    
    executor = ThreadPoolExecutor(max_workers=threads)

    

    try:
        with tqdm(total=total_tasks, desc="[+] Scanning", unit="req", ascii=" #") as pbar:
            futures = []
            for item in paths:
                if mode == "dir":
                    f = executor.submit(check_path, session, url, item, timeout, valid_code, results)
                else:
                    f = executor.submit(check_subdomain_dns, domain, item, timeout, resolver, results)

                f.add_done_callback(lambda _: pbar.update(1))
                futures.append(f)

            for f in futures:
                f.result()

        
        executor.shutdown(wait=False)
        elapsed_time = round(time.time() - start_time, 2)

        if ai_enabled and results:
            analyze_findings_ai(results, domain if mode == "sub" else url, api_key, api_url, model)

        return results, elapsed_time

    except KeyboardInterrupt:
        print(Fore.GREEN + "\n" + "-" * 50)
        print(Fore.RED + Style.BRIGHT + "\nAegis has been terminated by the user...")
        print(Fore.GREEN + "\n[===========]")
        print(Fore.GREEN + " Terminated!")
        print(Fore.GREEN + "[===========]")
        print(Fore.RED + "\n[!] Process interrupted by user (Ctrl+C). Exiting...")
        
        
        os._exit(0)


def finish(results, elapsed_time):
    print(Fore.GREEN + "\n" + "[" + "-" * 50 + "]")
    print(Fore.GREEN + "\n[===========]")
    print(Fore.GREEN + f" Finished!")
    print(Fore.GREEN + "[===========]")
    print(Fore.GREEN + "\n[+] Aegis has completed the scan !")

    if results:
        print(Fore.CYAN + f"[+] Total Found: {len(results)}")
        for res in results:
            print(res)
    else:
        print(Fore.YELLOW + "[!] No valid paths/subdomains were found.")

    print(Fore.GREEN + f"[+] Aegis has completed the scan in {elapsed_time} seconds. Exiting...")


if __name__ == "__main__":
    print_banner()
    args = parse_arguments()

    res = web_enumeration(
        args.mode, args.url, args.wordlist, args.timeout, 
        args.threads, args.match_codes, args.extensions, 
        args.ai, args.api_key, args.api_url, args.model
    )
    if res and res[0] is not None:
        results, elapsed_time = res
        finish(results, elapsed_time)