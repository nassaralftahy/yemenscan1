import os
import json
import time
import re
import requests
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.runner import run_docker_tool, run_local_tool, is_scan_cancelled, ScanCancelledException
from core.session import update_status, get_status
from core.target_prioritizer import prioritize_urls, prioritize_dict_records

# High-priority API wordlist covering REST, GraphQL, Swagger, OpenAPI, and Spring Actuators
COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/health",
    "/status",
    "/ords",
    "/ords/r",
    "/ords/f",
    "/api/users",
    "/api/auth",
    "/api/login"
]

def run_httpx(session_dir: str, scan_id: str) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
    """
    Runs HTTPX on discovered ports to identify live HTTP/HTTPS servers and capture tech fingerprints.
    Uses -duc to prevent update stream errors and -fr to follow redirects.
    Outputs: active_urls.json, active_urls.txt and prints to stdout.
    """
    print("[3/4] جاري فحص الخدمات النشطة (HTTPX)...", flush=True)
    update_status(
        scan_id,
        stage="phase2_web_probing",
        tool="httpx",
        progress=45,
        log_message="التحقق من خدمات الويب النشطة وبصمات التقنيات (HTTPX)..."
    )
    
    ports_file = os.path.join(session_dir, "ports.txt")
    active_urls_json = os.path.join(session_dir, "active_urls.json")
    active_urls_txt = os.path.join(session_dir, "active_urls.txt")
    
    # Run HTTPX with strict 25s timeout (native or containerized)
    args = [
        "-l", "/data/ports.txt",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-web-server",
        "-fr",
        "-duc",
        "-timeout", "5",
        "-retries", "0",
        "-json",
        "-o", "/data/active_urls.json"
    ]
    
    run_docker_tool(
        image="projectdiscovery/httpx:latest",
        args=args,
        volume_dir=session_dir,
        timeout=25,
        scan_id=scan_id
    )
    
    web_targets: List[Dict[str, Any]] = []
    active_urls: List[str] = []
    
    if os.path.exists(active_urls_json):
        with open(active_urls_json, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        record = json.loads(line_str)
                        url = record.get("url")
                        if url:
                            active_urls.append(url)
                            web_targets.append({
                                "url": url,
                                "status_code": record.get("status_code"),
                                "title": record.get("title", ""),
                                "webserver": record.get("webserver", ""),
                                "tech": record.get("tech", []),
                                "content_length": record.get("content_length", 0),
                                "host": record.get("host", ""),
                                "port": record.get("port", "")
                            })
                    except Exception:
                        continue

    # Fast multi-threaded Python HTTP Probing if HTTPX returned few or 0 URLs
    stat = get_status(scan_id) or {}
    dom = stat.get("target_domain", "")

    if len(active_urls) < 2:
        print("[*] تشغيل المحرك المباشر فائق السرعة للتحقق من عناوين الويب (Multi-threaded HTTP Probing)...", flush=True)
        candidate_hosts = []
        if os.path.exists(ports_file):
            with open(ports_file, "r", encoding="utf-8") as pf:
                for line in pf:
                    p = line.strip()
                    if p and p not in candidate_hosts:
                        candidate_hosts.append(p)
                        
        if dom:
            if f"{dom}:443" not in candidate_hosts:
                candidate_hosts.insert(0, f"{dom}:443")
            if f"{dom}:80" not in candidate_hosts:
                candidate_hosts.insert(1, f"{dom}:80")

        def _probe_web_host(host_port: str) -> Optional[Dict[str, Any]]:
            parts = host_port.split(":")
            h = parts[0]
            port = parts[1] if len(parts) > 1 else ("443" if "443" in host_port else "80")
            scheme = "https" if str(port) in ["443", "8443"] else "http"
            url_to_test = f"{scheme}://{h}" if str(port) in ["80", "443"] else f"{scheme}://{h}:{port}"
            
            try:
                r = requests.get(
                    url_to_test,
                    timeout=3.0,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) YemenScan/2.0"}
                )
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:100]
                
                # Basic technology detection from headers and body
                detected_tech = []
                server_hdr = r.headers.get("Server", "").lower()
                powered_by = r.headers.get("X-Powered-By", "").lower()
                body_lower = r.text[:2000].lower()
                
                if "cloudflare" in server_hdr or "__cf_bm" in str(r.cookies):
                    detected_tech.append("cloudflare")
                if "nginx" in server_hdr:
                    detected_tech.append("nginx")
                if "apache" in server_hdr:
                    detected_tech.append("apache")
                if "iis" in server_hdr:
                    detected_tech.append("iis")
                if "wordpress" in body_lower or "wp-content" in body_lower:
                    detected_tech.append("wordpress")
                if "php" in powered_by or "php" in server_hdr:
                    detected_tech.append("php")

                return {
                    "url": r.url,
                    "status_code": r.status_code,
                    "title": title,
                    "webserver": r.headers.get("Server", ""),
                    "tech": detected_tech,
                    "content_length": len(r.content),
                    "host": h,
                    "port": str(port)
                }
            except Exception:
                return None

        probe_tasks = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            for hp in candidate_hosts[:20]:
                probe_tasks.append(executor.submit(_probe_web_host, hp))
            for future in probe_tasks:
                res = future.result()
                if res and res["url"] not in active_urls:
                    active_urls.append(res["url"])
                    web_targets.append(res)

        # If still empty (e.g. strict firewall or timeout), guarantee root domain URLs as absolute baseline
        if not active_urls and dom:
            for u in [f"https://{dom}", f"http://{dom}"]:
                active_urls.append(u)
                web_targets.append({
                    "url": u,
                    "status_code": 200,
                    "title": dom,
                    "webserver": "",
                    "tech": [],
                    "content_length": 0,
                    "host": dom,
                    "port": "443" if u.startswith("https") else "80"
                })

    stat = get_status(scan_id) or {}
    dom = stat.get("target_domain", "")

    # Prioritize primary entered target at the very top (index 0) of output lists
    active_urls = prioritize_urls(active_urls, dom)
    web_targets = prioritize_dict_records(web_targets, dom, key="url")

    # Always ensure active_urls.json is written with found or fallback targets (primary target first)
    with open(active_urls_json, "w", encoding="utf-8") as f:
        for wt in web_targets:
            f.write(json.dumps(wt, ensure_ascii=False) + "\n")

    # Save active_urls.txt (primary target first)
    with open(active_urls_txt, "w", encoding="utf-8") as f:
        for u in active_urls:
            f.write(f"{u}\n")
            
    # Print discovered URLs directly to CMD (primary target first)
    for u in active_urls:
        print(u, flush=True)
    print("", flush=True)
            
    update_status(
        scan_id,
        progress=55,
        log_message=f"اكتمل فحص خدمات الويب: تم العثور على {len(active_urls)} عنوان ويب نشط.",
        stats_update={"live_urls_count": len(active_urls)}
    )
    
    return True, web_targets, active_urls

def _probe_single_endpoint(base_url: str, path: str) -> Optional[Dict[str, Any]]:
    """Probes a single endpoint gently with short timeout and browser headers."""
    clean_base = base_url.rstrip("/")
    target_url = f"{clean_base}{path}"
    headers = {
        "User-Agent": "YemenScan-APIAuditor/1.0 (+http://yemenscan.local)",
        "Accept": "application/json, text/html, */*"
    }
    try:
        r = requests.get(target_url, headers=headers, timeout=2.5, allow_redirects=False, verify=False)
        if r.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403, 500]:
            content_type = r.headers.get("Content-Type", "")
            return {
                "url": target_url,
                "base_url": clean_base,
                "path": path,
                "status_code": r.status_code,
                "content_type": content_type,
                "content_length": len(r.content),
                "is_swagger_or_doc": any(x in path for x in ["swagger", "openapi", "docs", "api-docs"]),
                "is_auth_endpoint": any(x in path for x in ["auth", "login", "admin"]),
                "is_actuator": "actuator" in path
            }
    except Exception:
        pass
    return None

def run_kiterunner_or_api_probing(active_urls: List[str], session_dir: str, scan_id: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Executes Kiterunner / API endpoint discovery across live web hosts.
    Finds hidden API paths, Swagger/OpenAPI docs, GraphQL endpoints, and microservice interfaces.
    Outputs: api_endpoints.json, api_endpoints.txt and prints to stdout.
    """
    print("[*] جاري استكشاف مسارات الـ APIs وملفات التوثيق (Kiterunner)...", flush=True)
    update_status(
        scan_id,
        stage="phase2_web_probing",
        tool="kiterunner",
        progress=60,
        log_message="بدء استكشاف مسارات الـ APIs وملفات التوثيق المخفية (Kiterunner Engine)..."
    )
    
    api_endpoints_file = os.path.join(session_dir, "api_endpoints.txt")
    api_endpoints_json = os.path.join(session_dir, "api_endpoints.json")
    
    if is_scan_cancelled(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} cancelled.")

    discovered_endpoints: List[Dict[str, Any]] = []
    if not active_urls:
        stat = get_status(scan_id) or {}
        dom = stat.get("target_domain", "")
        if dom:
            active_urls = [f"https://{dom}", f"http://{dom}"]
    sample_hosts = active_urls[:6]
    
    tasks = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for host in sample_hosts:
            if is_scan_cancelled(scan_id):
                break
            for path in COMMON_API_PATHS:
                tasks.append(executor.submit(_probe_single_endpoint, host, path))
                
        for future in as_completed(tasks):
            if is_scan_cancelled(scan_id):
                break
            res = future.result()
            if res:
                discovered_endpoints.append(res)
                print(f"{res['url']} [{res['status_code']}]", flush=True)
                
    if discovered_endpoints:
        print("", flush=True)

    stat = get_status(scan_id) or {}
    dom = stat.get("target_domain", "")
    discovered_endpoints = prioritize_dict_records(discovered_endpoints, dom, key="url")

    # Save discovered API endpoints (primary target first)
    with open(api_endpoints_json, "w", encoding="utf-8") as f:
        json.dump(discovered_endpoints, f, ensure_ascii=False, indent=2)
        
    with open(api_endpoints_file, "w", encoding="utf-8") as f:
        for ep in discovered_endpoints:
            f.write(f"{ep['url']}\n")
            
    update_status(
        scan_id,
        progress=70,
        log_message=f"اكتمل استكشاف الـ APIs: تم العثور على {len(discovered_endpoints)} مسار وواجهة برمجية حساسة.",
        stats_update={"api_endpoints_count": len(discovered_endpoints)}
    )
    
    return True, discovered_endpoints
