import os
import json
import time
import uuid
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scans")

_STATUS_LOCK = threading.Lock()

def ensure_scans_dir() -> str:
    """Ensures the base scans directory exists."""
    os.makedirs(SCANS_DIR, exist_ok=True)
    return SCANS_DIR

def create_scan_session(domain: str) -> str:
    """
    Creates a new scan session with a unique ID and initialized status file.
    Format: scan_YYYYMMDD_HHMMSS_<rand_suffix>_<clean_domain>
    """
    ensure_scans_dir()
    clean_domain = "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rand_suffix = uuid.uuid4().hex[:6]
    scan_id = f"scan_{timestamp}_{rand_suffix}_{clean_domain}"
    
    from core.runner import clear_scan_cancelled
    clear_scan_cancelled(scan_id)
    
    session_dir = os.path.join(SCANS_DIR, scan_id)
    os.makedirs(session_dir, exist_ok=True)
    
    initial_status = {
        "scan_id": scan_id,
        "target_domain": domain,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "current_stage": "queued",
        "current_tool": "none",
        "progress_percentage": 0,
        "stage_labels": {
            "phase1": "الاستكشاف وفحص المنافذ (Discovery & Port Scanning)",
            "phase2": "تحديد خدمات الويب واستكشاف الـ APIs (Web & API Probing)",
            "phase3": "فحص الثغرات الأمنية (Vulnerability Scanning)"
        },
        "stats": {
            "subdomains_count": 0,
            "open_ports_count": 0,
            "live_urls_count": 0,
            "api_endpoints_count": 0,
            "vulnerabilities_count": 0,
            "vuln_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        },
        "logs": [
            f"[{datetime.now().strftime('%H:%M:%S')}] تم إنشاء جلسة الفحص للنطاق: {domain}"
        ],
        "is_completed": False,
        "has_error": False,
        "error_message": None
    }
    
    status_file = os.path.join(session_dir, "status.json")
    with _STATUS_LOCK:
        with open(status_file, "w", encoding="utf-8") as f:
            json.dump(initial_status, f, ensure_ascii=False, indent=2)
        
    return scan_id

def get_session_dir(scan_id: str) -> str:
    """Returns the absolute path to a scan session directory."""
    return os.path.join(SCANS_DIR, scan_id)

def get_status(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves current status data for a specific scan ID."""
    session_dir = get_session_dir(scan_id)
    status_file = os.path.join(session_dir, "status.json")
    if not os.path.exists(status_file):
        return None
    with _STATUS_LOCK:
        try:
            with open(status_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

def update_status(
    scan_id: str,
    stage: Optional[str] = None,
    tool: Optional[str] = None,
    progress: Optional[int] = None,
    log_message: Optional[str] = None,
    stats_update: Optional[Dict[str, Any]] = None,
    is_completed: Optional[bool] = None,
    error: Optional[str] = None
) -> None:
    """Updates session status file atomically and safely with lock."""
    session_dir = get_session_dir(scan_id)
    status_file = os.path.join(session_dir, "status.json")
    
    with _STATUS_LOCK:
        if not os.path.exists(status_file):
            return
        try:
            with open(status_file, "r", encoding="utf-8") as f:
                status = json.load(f)
        except Exception:
            return
            
        status["updated_at"] = datetime.now().isoformat()
        
        if stage is not None:
            status["current_stage"] = stage
        if tool is not None:
            status["current_tool"] = tool
        if progress is not None:
            status["progress_percentage"] = max(0, min(100, progress))
        if log_message:
            timestamp_str = datetime.now().strftime("%H:%M:%S")
            status["logs"].append(f"[{timestamp_str}] {log_message}")
        if stats_update:
            for k, v in stats_update.items():
                if k == "vuln_by_severity" and isinstance(v, dict):
                    status["stats"]["vuln_by_severity"].update(v)
                else:
                    status["stats"][k] = v
        if is_completed is not None:
            status["is_completed"] = is_completed
        if error is not None:
            status["has_error"] = True
            status["error_message"] = error
            timestamp_str = datetime.now().strftime("%H:%M:%S")
            status["logs"].append(f"[{timestamp_str}] خطأ: {error}")
            
        temp_file = os.path.join(session_dir, f"status_{uuid.uuid4().hex[:4]}.tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(status, f, ensure_ascii=False, indent=2)
            os.replace(temp_file, status_file)
        except Exception:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass

def list_all_scans() -> List[Dict[str, Any]]:
    """Lists all available scan sessions with summary metrics."""
    ensure_scans_dir()
    scans = []
    for item in os.listdir(SCANS_DIR):
        item_path = os.path.join(SCANS_DIR, item)
        if os.path.isdir(item_path):
            status = get_status(item)
            if status:
                scans.append({
                    "scan_id": status["scan_id"],
                    "target_domain": status["target_domain"],
                    "created_at": status["created_at"],
                    "current_stage": status["current_stage"],
                    "progress": status["progress_percentage"],
                    "is_completed": status["is_completed"],
                    "stats": status["stats"]
                })
    # Sort scans descending by creation time
    scans.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return scans

def stop_scan_session(scan_id: str) -> bool:
    """
    Marks a scan session as stopped, triggers process and container termination,
    and updates status.json with the stopped state.
    """
    from core.runner import mark_scan_cancelled
    mark_scan_cancelled(scan_id)
    update_status(
        scan_id,
        stage="stopped",
        tool="none",
        is_completed=True,
        log_message="🛑 تم إرسال أمر إيقاف عملية الفحص بواسطة المستخدم."
    )
    return True
