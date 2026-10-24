import os
import time
from core.session import get_session_dir, update_status
from core.runner import is_scan_cancelled, ScanCancelledException
from core.stage1_discovery import run_subfinder, run_naabu
from core.stage2_web_probing import run_httpx, run_kiterunner_or_api_probing
from core.stage3_vulnerabilities import (
    prepare_nuclei_targets,
    run_nuclei,
    run_optimized_nuclei,
    run_wapiti_dast,
    unify_and_save_vulnerabilities
)

def run_full_pipeline(domain: str, scan_id: str) -> None:
    """
    Executes the end-to-end 3-phase Black-box attack surface management pipeline:
    1. Phase 1: Subfinder (Subdomains) -> Naabu (Ports)
    2. Phase 2: HTTPX (Live Web Servers) -> Kiterunner (API & Route Discovery)
    3. Phase 3: Nuclei (CVEs & OWASP API Top 10) + Wapiti (DAST Web Top 10) -> Unified Report
    Supports real-time cancellation.
    """
    session_dir = get_session_dir(scan_id)
    
    try:
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled before starting.")

        print(f"[*] بدء عملية الاستطلاع والفحص الأمني الشامل للنطاق: {domain}\n", flush=True)
        update_status(
            scan_id,
            stage="phase1_discovery",
            progress=5,
            log_message=f"بدء تنفيذ خط الفحص الشامل للنطاق المستهدف: {domain}"
        )
        
        # -------------------------------------------------------------
        # Phase 1: Discovery & Port Scanning
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_sub, subdomains = run_subfinder(domain, session_dir, scan_id)
        if not subdomains:
            subdomains = [domain]
            
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_ports, open_ports = run_naabu(subdomains, session_dir, scan_id)
        
        # -------------------------------------------------------------
        # Phase 2: Web & API Probing
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_http, web_targets, active_urls = run_httpx(session_dir, scan_id)
        
        # If no ports or urls were detected, probe domain directly on 80/443
        if not active_urls:
            active_urls = [f"http://{domain}", f"https://{domain}"]
            
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_api, api_endpoints = run_kiterunner_or_api_probing(active_urls, session_dir, scan_id)
        
        # -------------------------------------------------------------
        # Phase 3: Vulnerability Scanning
        # -------------------------------------------------------------
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        all_targets = prepare_nuclei_targets(session_dir)
        
        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_nuc, nuclei_findings = run_nuclei(session_dir, scan_id)

        if is_scan_cancelled(scan_id):
            raise ScanCancelledException(f"Scan {scan_id} was cancelled.")
        ok_wap, wapiti_findings = run_wapiti_dast(session_dir, scan_id, active_urls)
        
        # Unify and generate executive findings (completely isolated inside session_dir)
        unify_and_save_vulnerabilities(session_dir, scan_id, nuclei_findings, wapiti_findings)

    except ScanCancelledException:
        print(f"[*] [STOPPED] تم إيقاف عملية الفحص للنطاق: {domain} بناءً على طلب المستخدم.\n", flush=True)
        update_status(
            scan_id,
            stage="stopped",
            tool="none",
            is_completed=True,
            log_message="🛑 تم إيقاف عملية الفحص بنجاح بناءً على طلب المستخدم."
        )
    except Exception as e:
        update_status(
            scan_id,
            error=f"حدث استثناء غير متوقع أثناء تشغيل خط الفحص: {str(e)}"
        )
