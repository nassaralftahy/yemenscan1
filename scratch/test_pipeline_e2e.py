# -*- coding: utf-8 -*-
"""
End-to-end verification script for YemenScan vulnerability pipeline.
Tests:
- Full pipeline run with Nuclei (80 templates, critical+high+medium) + Wapiti DAST
- Cross-scanner deduplication & integration
- Ingestion into PostgreSQL
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.session import create_scan_session, get_status
from core.pipeline import run_full_pipeline

target = "scanme.nmap.org"
print(f"[*] Starting test scan on: {target}")

scan_id = create_scan_session(target)
print(f"[+] Created session: {scan_id}")

start_time = time.time()
try:
    run_full_pipeline(domain=target, scan_id=scan_id)
    elapsed = time.time() - start_time
    print(f"\n[+] Pipeline execution finished in {elapsed:.1f}s.")
    
    st = get_status(scan_id)
    print(f"[+] Status: progress={st.get('progress')}, completed={st.get('is_completed')}")
    print(f"[+] Log: {st.get('log_message')}")
    print(f"[+] Stats: {st.get('stats')}")
except Exception as e:
    print(f"[-] Pipeline error: {e}")
    import traceback
    traceback.print_exc()
