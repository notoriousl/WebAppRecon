import requests
import socket
import argparse
import re
import threading
import queue
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import urllib3 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

subdomain_results = []
resolved_ips = {}
vhost_results = []
api_endpoints = set()

# ------------ Subdomain Enumeration ------------
def get_subdomains(domain, verbose=False):
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
        if verbose:
            for sub in subdomains:
                console.print(f"[cyan]{sub}[/cyan]")
        console.print(f"[green][+] Found {len(subdomains)} subdomains[/green]")
        return list(subdomains)
    except Exception as e:
        console.print(f"[red][-] Failed to query crt.sh: {e}[/red]")
        return []

# ------------ DNS Resolution ------------
def resolve_worker(q, progress, task_id, verbose):
    while not q.empty():
        sub = q.get()
        try:
            ip = socket.gethostbyname(sub)
            resolved_ips[sub] = ip
            if verbose:
                console.print(f"[blue]{sub} -> {ip}[/blue]")
        except:
            resolved_ips[sub] = None
            if verbose:
                console.print(f"[red]{sub} -> Unresolved[/red]")
        progress.advance(task_id)
        q.task_done()

def resolve_subdomains(subdomains, threads=10, verbose=False):
    console.rule("[bold green]🌐 DNS Resolution")
    q = queue.Queue()
    for sub in subdomains:
        q.put(sub)

    with Progress(SpinnerColumn(), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Resolving...", total=len(subdomains))

        for _ in range(threads):
            t = threading.Thread(target=resolve_worker, args=(q, progress, task, verbose))
            t.daemon = True
            t.start()
        q.join()

# ------------ Virtual Host Fuzzing ------------
def vhost_worker(ip, q, progress, task_id, use_https, verbose):
    while not q.empty():
        host = q.get().strip()
        headers = {'Host': host}
        scheme = "https" if use_https else "http"
        try:
            response = requests.get(f"{scheme}://{ip}", headers=headers, timeout=5, verify=False)
            if response.status_code in [200, 301, 302]:
                vhost_results.append((host, response.status_code))
                if verbose:
                    console.print(f"[yellow]{host} -> {response.status_code}[/yellow]")
        except:
            if verbose:
                console.print(f"[red]{host} -> Failed[/red]")
        progress.advance(task_id)
        q.task_done()

def fuzz_virtual_hosts(ip, wordlist, threads=10, use_https=False, verbose=False):
    console.rule("[bold yellow]🏷 Virtual Host Fuzzing")
    q = queue.Queue()
    for word in wordlist:
        q.put(word)

    with Progress(SpinnerColumn(), BarColumn(), TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Fuzzing...", total=len(wordlist))
        for _ in range(threads):
            t = threading.Thread(target=vhost_worker, args=(ip, q, progress, task, use_https, verbose))
            t.daemon = True
            t.start()
        q.join()

# ------------ API Endpoint Extraction ------------
def extract_api_endpoints(url, verbose=False):
    console.rule("[bold magenta]🔗 API Endpoint, JWT, and API Key Extraction")
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        js_urls = [urljoin(url, script['src']) for script in scripts if script['src'].endswith('.js')]

        # Patterns
        api_pattern = re.compile(r"https?://[^\s\"']+")
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+')
        key_pattern = re.compile(r'(api[-]?key|access[-]?token|token)[\'"\s:=]{1,5}([A-Za-z0-9_\-]{10,})', re.IGNORECASE)

        for js_url in js_urls:
            try:
                js_code = requests.get(js_url, timeout=5).text

                # Extract API endpoints
                for match in api_pattern.findall(js_code):
                    if '/api/' in match:
                        api_endpoints.add(match)
                        if verbose:
                            console.print(f"[magenta]{match}[/magenta]")

                # Extract JWTs
                for jwt in jwt_pattern.findall(js_code):
                    api_endpoints.add(f"[JWT] {jwt}")
                    if verbose:
                        console.print(f"[red][JWT][/red] {jwt}")

                # Extract API keys / tokens
                for key_match in key_pattern.findall(js_code):
                    label, key = key_match
                    api_endpoints.add(f"[KEY] {label}: {key}")
                    if verbose:
                        console.print(f"[yellow][KEY][/yellow] {label}: {key}")

            except Exception as e:
                if verbose:
                    console.print(f"[red]Failed to fetch {js_url}: {e}[/red]")
                continue

        console.print(f"[green][+] Found {len(api_endpoints)} items (API endpoints / JWTs / keys)[/green]")
        return list(api_endpoints)

    except Exception as e:
        console.print(f"[red][-] Failed to extract: {e}[/red]")
        return []


# ------------ Output & Summary ------------
def prompt_save_output(domain):
    choice = input("\nDo you want to save the output to text files? (y/n): ").lower()
    if choice != 'y':
        return

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

    if resolved_ips:
        table = Table(title="DNS Resolution", style="green")
        table.add_column("Subdomain", justify="left")
        table.add_column("IP Address", justify="left")
        for sub, ip in list(resolved_ips.items())[:10]:
            table.add_row(sub, ip or "Unresolved")
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
    parser = argparse.ArgumentParser(description="🚀 Rich Recon Tool")
    parser.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("--ip", help="Target IP for virtual host fuzzing")
    parser.add_argument("--wl", help="Path to a wordlist for virtual host fuzzing")
    parser.add_argument("--threads", type=int, default=10, help="Thread count (default=10)")
    parser.add_argument("--mode", choices=["1", "2", "3", "4", "5"], help="1=Subdomains, 2=DNS, 3=VHost, 4=API, 5=All")
    parser.add_argument("--https", action="store_true", help="Use HTTPS for virtual host fuzzing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        return

    mode = args.mode or input(
        "\nChoose what to perform:\n"
        "[1] Subdomain Enumeration\n"
        "[2] DNS Resolution\n"
        "[3] Virtual Host Fuzzing\n"
        "[4] API Endpoint Extraction\n"
        "[5] ALL\n> "
    )

    global subdomain_results

    if mode == "1" or mode == "5":
        subdomain_results = get_subdomains(args.domain, verbose=args.verbose)

    if mode == "2" or mode == "5":
        if not subdomain_results:
            subdomain_results = get_subdomains(args.domain, verbose=args.verbose)
        resolve_subdomains(subdomain_results, threads=args.threads, verbose=args.verbose)

    if mode == "3" or mode == "5":
        ip = args.ip or resolved_ips.get(args.domain)
        if not ip:
            try:
                ip = socket.gethostbyname(args.domain)
            except:
                ip = input("Enter IP for virtual host fuzzing: ")

        if not args.wl:
            path = input("Enter path to wordlist or press Enter to use default: ")
            if not path:
                wordlist = [f"test{i}.{args.domain}" for i in range(1, 6)]
            else:
                with open(path, 'r') as f:
                    wordlist = f.readlines()
        else:
            with open(args.wl, 'r') as f:
                wordlist = f.readlines()

        fuzz_virtual_hosts(ip, wordlist, threads=args.threads, use_https=args.https, verbose=args.verbose)

    if mode == "4" or mode == "5":
        extract_api_endpoints(f"http://{args.domain}", verbose=args.verbose)

    prompt_save_output(args.domain)
    display_summary()

if _name_ == "_main_":
    main()
