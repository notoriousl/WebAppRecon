import requests
import socket
import argparse
import re
import threading
import queue
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

subdomain_results = []
resolved_ips = {}
vhost_results = []
api_endpoints = set()

# ------------ Subdomain Enumeration ------------
def get_subdomains(domain):
    console.rule("[bold blue]🔍 Subdomain Enumeration")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        json_data = response.json()
        subdomains = set()
        for entry in json_data:
            name = entry.get('name_value', '')
            for sub in name.split('\n'):
                if domain in sub:
                    subdomains.add(sub.strip())
        console.print(f"[green][+] Found {len(subdomains)} subdomains[/green]")
        return list(subdomains)
    except Exception as e:
        console.print(f"[red][-] Failed to query crt.sh: {e}[/red]")
        return []

# ------------ DNS Resolution with Progress ------------
def resolve_worker(q, progress, task_id):
    while not q.empty():
        sub = q.get()
        try:
            ip = socket.gethostbyname(sub)
            resolved_ips[sub] = ip
        except:
            resolved_ips[sub] = None
        progress.advance(task_id)
        q.task_done()

def resolve_subdomains(subdomains, threads=10):
    console.rule("[bold green]🌐 DNS Resolution")
    q = queue.Queue()
    for sub in subdomains:
        q.put(sub)

    with Progress(SpinnerColumn(), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Resolving...", total=len(subdomains))

        for _ in range(threads):
            t = threading.Thread(target=resolve_worker, args=(q, progress, task))
            t.daemon = True
            t.start()
        q.join()

# ------------ Virtual Host Fuzzing ------------
def vhost_worker(ip, q, progress, task_id):
    while not q.empty():
        host = q.get().strip()
        headers = {'Host': host}
        try:
            response = requests.get(f"http://{ip}", headers=headers, timeout=5)
            if response.status_code in [200, 301, 302]:
                vhost_results.append((host, response.status_code))
        except:
            pass
        progress.advance(task_id)
        q.task_done()

def fuzz_virtual_hosts(ip, wordlist, threads=10):
    console.rule("[bold yellow]🏷 Virtual Host Fuzzing")
    q = queue.Queue()
    for word in wordlist:
        q.put(word)

    with Progress(SpinnerColumn(), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Fuzzing...", total=len(wordlist))
        for _ in range(threads):
            t = threading.Thread(target=vhost_worker, args=(ip, q, progress, task))
            t.daemon = True
            t.start()
        q.join()

# ------------ API Endpoint & Sensitive Token Extraction ------------
def extract_api_endpoints_and_tokens(url):
    console.rule("[bold magenta]🔗 API Endpoint & Sensitive Data Extraction")
    sensitive_data = {
        "api_keys": set(),
        "jwt_tokens": set(),
        "emails": set()
    }
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        js_urls = [urljoin(url, script['src']) for script in scripts if script['src'].endswith('.js')]

        # Regex patterns
        api_pattern = re.compile(r"https?://[^\s\"']+")
        key_pattern = re.compile(r"(?i)(api_key|apikey|key|token|secret)[\s\"'=:]+[\"']?([a-zA-Z0-9\-_]{10,})[\"']?")
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+")
        email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

        for js_url in js_urls:
            try:
                js_code = requests.get(js_url, timeout=5).text

                # Extract API URLs
                matches = api_pattern.findall(js_code)
                for match in matches:
                    if '/api/' in match:
                        api_endpoints.add(match)

                # Extract sensitive data
                for match in key_pattern.findall(js_code):
                    sensitive_data["api_keys"].add(match[1])
                for match in jwt_pattern.findall(js_code):
                    sensitive_data["jwt_tokens"].add(match)
                for match in email_pattern.findall(js_code):
                    sensitive_data["emails"].add(match)

            except Exception as js_error:
                console.print(f"[red][-] Could not fetch JS: {js_error}[/red]")
                continue

        # Show results
        console.print(f"[green][+] Found {len(api_endpoints)} API endpoints[/green]")
        console.print(f"[red][!] Found {len(sensitive_data['api_keys'])} API keys[/red]")
        console.print(f"[red][!] Found {len(sensitive_data['jwt_tokens'])} JWT tokens[/red]")
        console.print(f"[yellow][!] Found {len(sensitive_data['emails'])} emails[/yellow]")

        # Save results
        with open("sensitive_data.txt", 'w') as f:
            f.write("[API Endpoints]\n")
            for api in api_endpoints:
                f.write(f"{api}\n")
            f.write("\n[API Keys / Tokens]\n")
            for key in sensitive_data["api_keys"]:
                f.write(f"{key}\n")
            f.write("\n[JWT Tokens]\n")
            for jwt in sensitive_data["jwt_tokens"]:
                f.write(f"{jwt}\n")
            f.write("\n[Emails]\n")
            for email in sensitive_data["emails"]:
                f.write(f"{email}\n")

        return list(api_endpoints)

    except Exception as e:
        console.print(f"[red][-] Failed to extract API endpoints or keys: {e}[/red]")
        return []

# ------------ Output & Summary ------------
def save_output(domain):
    with open(f"{domain}_subdomains.txt", 'w') as f:
        for sub in subdomain_results:
            f.write(f"{sub}\n")

    with open(f"{domain}_resolved.txt", 'w') as f:
        for sub, ip in resolved_ips.items():
            f.write(f"{sub} -> {ip or 'Unresolved'}\n")

    with open(f"{domain}_vhosts.txt", 'w') as f:
        for host, code in vhost_results:
            f.write(f"{host} -> {code}\n")

    with open(f"{domain}_api_endpoints.txt", 'w') as f:
        for api in api_endpoints:
            f.write(f"{api}\n")

    console.print(f"[bold green]\n✅ Results saved to: {domain}_*.txt[/bold green]")

def display_summary():
    if subdomain_results:
        table = Table(title="Subdomains", style="cyan")
        table.add_column("Subdomain", justify="left")
        for sub in subdomain_results[:10]:
            table.add_row(sub)
        console.print(table)

    if vhost_results:
        table = Table(title="Virtual Hosts", style="yellow")
        table.add_column("Host", justify="left")
        table.add_column("Status", justify="center")
        for host, code in vhost_results:
            table.add_row(host, str(code))
        console.print(table)

    if api_endpoints:
        table = Table(title="API Endpoints", style="magenta")
        table.add_column("Endpoint", justify="left")
        for api in list(api_endpoints)[:10]:
            table.add_row(api)
        console.print(table)

# ------------ CLI Entry Point ------------
def main():
    parser = argparse.ArgumentParser(description="🚀 Rich Recon Tool: Subdomains, DNS, VHosts, APIs")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--vhost-ip", help="Target IP for virtual host fuzzing")
    parser.add_argument("--vhost-wordlist", help="Path to a wordlist for virtual host fuzzing")
    parser.add_argument("--threads", type=int, default=10, help="Thread count (default=10)")
    args = parser.parse_args()

    global subdomain_results
    subdomain_results = get_subdomains(args.domain)

    resolve_subdomains(subdomain_results, threads=args.threads)

    if args.vhost_ip and args.vhost_wordlist:
        try:
            with open(args.vhost_wordlist, 'r') as f:
                wordlist = f.readlines()
            fuzz_virtual_hosts(args.vhost_ip, wordlist, threads=args.threads)
        except Exception as e:
            console.print(f"[red][-] Error loading wordlist: {e}[/red]")

    extract_api_endpoints_and_tokens(f"http://{args.domain}")

    save_output(args.domain)
    display_summary()

if __name__ == "__main__":
    main()

