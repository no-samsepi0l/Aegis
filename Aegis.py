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

warnings.filterwarnings("ignore", category=UserWarning, module="requests")
init(autoreset=True)


# Parse command-line arguments.
def parse_arguments():
    parser = argparse.ArgumentParser(description="Aegis - High-Performance Web Enumeration Tool")
    parser.add_argument("-m", "--mode", choices=["dir", "sub"], default="dir",
                        help="Scan mode: 'dir' for directory fuzzing or 'sub' for subdomain enumeration (default: dir)")
    parser.add_argument("-u", "--url", required=True, help="Full URL or domain of the target (e.g., http://example.com/)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Timeout in seconds (default: 1.5)")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument("-mc", "--match-codes", type=str, default="200,301,302,308,403", 
                        help="HTTP status codes to display (default: 200,301,302,308,403)")
    parser.add_argument("-x", "--extensions", type=str, default="", 
                        help="File extensions to append (e.g., php,html,txt)")
    return parser.parse_args()


# Display the application banner.
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
 """)
    print(Fore.GREEN + "[=" + "=" * 35 + "=]")  


# Check if a specific URL path exists and matches expected status codes.
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


# Resolve DNS A records for a given subdomain.
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


# Run the multithreaded enumeration workflow.
def web_enumeration(mode, target_input, wordlist_path, timeout, threads, match_codes_str, extensions_str):
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
        return results, elapsed_time

    except KeyboardInterrupt:
        print(Fore.GREEN + "\n" + "-" * 50)
        print(Fore.RED + Style.BRIGHT + "\nAegis has been terminated by the user...")
        print(Fore.GREEN + "\n[===========]")
        print(Fore.GREEN + " Terminated!")
        print(Fore.GREEN + "[===========]")
        print(Fore.RED + "\n[!] Process interrupted by user (Ctrl+C). Exiting...")
        os._exit(0)


# Print scan results summary and elapsed time.
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
        args.threads, args.match_codes, args.extensions
    )
    if res and res[0] is not None:
        results, elapsed_time = res
        finish(results, elapsed_time)
