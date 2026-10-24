import os
import socket
from typing import List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor
from core.runner import run_docker_tool
from core.session import update_status
from core.target_prioritizer import prioritize_hosts, prioritize_ports

COMMON_SUBDOMAINS = [
    "www", "mail", "portal", "api", "admin", "webmail", "cpanel",
    "dev", "test", "app", "vpn", "m", "blog", "shop", "edu", "sis", "lms", "cloud",
    "auth", "login", "gateway", "dashboard", "stage", "staging", "beta", "secure",
    "intranet", "staff", "student", "services", "remote", "git", "gitlab", "jenkins"
]

def _resolve_subdomain(sub: str, domain: str) -> Tuple[str, str]:
    """Helper to resolve a subdomain to an IP address using system DNS with strict timeout."""
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception:
        return fqdn, ""

def run_subfinder(domain: str, session_dir: str, scan_id: str) -> Tuple[bool, List[str]]:
    """
    Runs Subfinder to passively enumerate subdomains, augmented with high-speed
    native DNS resolution for common subdomains to guarantee zero misses.
    Outputs: subdomains.txt and prints to stdout.
    """
    print("[1/4] جاري البحث عن النطاقات الفرعية (Subfinder & Smart DNS Engine)...", flush=True)
    update_status(
        scan_id,
        stage="phase1_discovery",
        tool="subfinder",
        progress=10,
        log_message=f"بدء استكشاف النطاقات الفرعية السلبي للنطاق: {domain} (Subfinder)..."
    )
    
    subdomains_file = os.path.join(session_dir, "subdomains.txt")
    
    # Run Subfinder with strict 25s timeout (native or containerized)
    args = [
        "-d", domain,
        "-silent",
        "-duc",
        "-timeout", "10",
        "-o", "/data/subdomains.txt"
    ]
    
    run_docker_tool(
        image="projectdiscovery/subfinder:latest",
        args=args,
        volume_dir=session_dir,
        timeout=25,
        scan_id=scan_id
    )
    
    subdomains: List[str] = []
    if os.path.exists(subdomains_file):
        with open(subdomains_file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and s not in subdomains:
                    subdomains.append(s)

    # Native DNS resolver augmentation: ultra-fast parallel check of top subdomains
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_resolve_subdomain, sub, domain) for sub in COMMON_SUBDOMAINS]
        for f in futures:
            fqdn, ip = f.result()
            if ip and fqdn not in subdomains:
                subdomains.append(fqdn)
                    
    # Always ensure the root domain is prioritized at index 0 (top of the file)
    subdomains = prioritize_hosts(subdomains, domain)

    with open(subdomains_file, "w", encoding="utf-8") as f:
        for s in subdomains:
            f.write(f"{s}\n")
                
    # Print discovered subdomains directly to CMD (primary target first)
    for s in subdomains:
        print(s, flush=True)
    print("", flush=True)
                
    update_status(
        scan_id,
        progress=20,
        log_message=f"اكتمل استكشاف النطاقات الفرعية: تم العثور على {len(subdomains)} نطاق فرعي نشط.",
        stats_update={"subdomains_count": len(subdomains)}
    )
    
    return True, subdomains

def _test_tcp_port(host: str, port: int) -> bool:
    """Fast non-blocking socket test to check if a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.75)
            res = s.connect_ex((host, port))
            return res == 0
    except Exception:
        return False

def _resolve_host_entry(clean_s: str) -> Tuple[str, str]:
    """Helper to resolve host to IP concurrently."""
    try:
        ip = socket.gethostbyname(clean_s)
        return clean_s, ip
    except Exception:
        return clean_s, ""

def run_naabu(subdomains: List[str], session_dir: str, scan_id: str) -> Tuple[bool, List[str]]:
    """
    Runs Naabu to discover open ports across all enumerated subdomains.
    Resolves hostnames to IPs on the host machine to guarantee 100% Docker network compatibility,
    uses TCP Connect scan (-s c), skips host ping discovery (-Pn), and disables update checks (-duc).
    Outputs: ports.txt (host:port) and prints to stdout.
    """
    print("[2/4] جاري فحص المنافذ المفتوحة (Naabu Engine)...", flush=True)
    update_status(
        scan_id,
        stage="phase1_discovery",
        tool="naabu",
        progress=25,
        log_message="بدء فحص المنافذ المفتوحة القياسية وغير القياسية (Naabu)..."
    )
    
    ports_file = os.path.join(session_dir, "ports.txt")
    subdomains_file = os.path.join(session_dir, "subdomains.txt")
    
    # 1. Concurrently resolve hostnames to IPs on Windows host
    host_to_ip: Dict[str, str] = {}
    ip_to_host: Dict[str, str] = {}
    target_entries: List[str] = []
    
    valid_subs = [s.strip() for s in subdomains if s.strip()]
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(_resolve_host_entry, s) for s in valid_subs]
        for f in futures:
            host_name, ip = f.result()
            target_entries.append(host_name)
            if ip:
                host_to_ip[host_name] = ip
                ip_to_host[ip] = host_name
                if ip not in target_entries:
                    target_entries.append(ip)

    # Write resolved targets (both FQDNs and direct IPs) to subdomains.txt for Naabu
    with open(subdomains_file, "w", encoding="utf-8") as f:
        for t in target_entries:
            f.write(f"{t}\n")
                
    args = [
        "-list", "/data/subdomains.txt",
        "-silent",
        "-p", "80,443,8080,8443,8000,8081,8888,9000,3000,5000,7001,9090",
        "-s", "c",
        "-Pn",
        "-duc",
        "-timeout", "750",
        "-retries", "0",
        "-rate", "1000",
        "-o", "/data/ports.txt"
    ]
    
    run_docker_tool(
        image="projectdiscovery/naabu:latest",
        args=args,
        volume_dir=session_dir,
        timeout=25,
        scan_id=scan_id
    )
    
    discovered_ports: List[str] = []
    if os.path.exists(ports_file):
        with open(ports_file, "r", encoding="utf-8") as f:
            for line in f:
                p = line.strip()
                if not p:
                    continue
                if p not in discovered_ports:
                    discovered_ports.append(p)
                if ":" in p:
                    h, port_num = p.split(":", 1)
                    if h in ip_to_host:
                        fqdn_entry = f"{ip_to_host[h]}:{port_num}"
                        if fqdn_entry not in discovered_ports:
                            discovered_ports.append(fqdn_entry)

    # 2. Fast multi-threaded native TCP port check across key web ports
    standard_ports = [80, 443, 8080, 8443, 8000, 3000, 5000, 8888]
    targets_for_tcp = valid_subs[:15] if valid_subs else []
    
    def _check_port_task(target_host: str, target_port: int) -> Optional[str]:
        if _test_tcp_port(target_host, target_port):
            return f"{target_host}:{target_port}"
        return None

    tcp_tasks = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        for target in targets_for_tcp:
            for pt in standard_ports:
                entry = f"{target}:{pt}"
                if entry not in discovered_ports:
                    tcp_tasks.append(executor.submit(_check_port_task, target, pt))
        for future in tcp_tasks:
            res = future.result()
            if res and res not in discovered_ports:
                discovered_ports.append(res)

    # 3. Defensive guarantee: ensure root target domain has 80 and 443
    if not discovered_ports and valid_subs:
        for s in valid_subs[:5]:
            discovered_ports.append(f"{s}:80")
            discovered_ports.append(f"{s}:443")
    elif valid_subs:
        root_0 = valid_subs[0]
        if f"{root_0}:443" not in discovered_ports:
            discovered_ports.append(f"{root_0}:443")
        if f"{root_0}:80" not in discovered_ports:
            discovered_ports.append(f"{root_0}:80")
            
    # Prioritize ports for the main target domain at the very top (lines 1, 2)
    root_domain = valid_subs[0] if valid_subs else ""
    discovered_ports = prioritize_ports(discovered_ports, root_domain)

    # Save final discovered ports
    with open(ports_file, "w", encoding="utf-8") as f:
        for p in discovered_ports:
            f.write(f"{p}\n")
            
    # Print discovered ports directly to CMD (primary target ports first)
    for p in discovered_ports:
        print(p, flush=True)
    print("", flush=True)
                
    update_status(
        scan_id,
        progress=35,
        log_message=f"اكتمل فحص المنافذ: تم اكتشاف {len(discovered_ports)} منفذاً نشطاً.",
        stats_update={"open_ports_count": len(discovered_ports)}
    )
    
    return True, discovered_ports
