"""
Strict Target Validation Layer for YemenScan Attack Surface Management.

Provides enterprise-grade domain validation, including:
1. URL and input sanitization (scheme, port, path, query, trailing characters).
2. RFC 1035 / RFC 1123 compliant Regex syntax verification.
3. Top-Level Domain (TLD) validation with blacklist of fake/internal pseudo-TLDs.
4. Active DNS Resolution (A/AAAA records) using socket with thread timeout.
5. Protection against Sinkhole IPs, Wildcard DNS, and Loopback/SSRF targets.
"""

import re
import socket
import ipaddress
import uuid
import concurrent.futures
from urllib.parse import urlparse
from typing import List, Tuple, Optional, Set


class TargetValidationError(Exception):
    """Exception raised when a domain fails validation checks."""
    def __init__(self, message: str, status_code: int = 400, code: str = "INVALID_TARGET"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


# RFC 1123 label regex: 1-63 chars, alphanumeric and hyphens, no leading/trailing hyphen
LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

# Known pseudo-TLDs or non-public internal zones that must be rejected
BLOCKED_PSEUDO_TLDS: Set[str] = {
    "local", "localhost", "internal", "test", "example", "invalid",
    "lan", "home", "corp", "intra", "onion", "arpa"
}

# Known sinkhole, wildcard, or bogus IP addresses returned by parked/compromised DNS or ISP hijacks
SINKHOLE_IPS: Set[str] = {
    "0.0.0.0",
    "127.0.53.53",       # ICANN name collision error
    "255.255.255.255",
    "198.105.244.11",    # Search Guide / Frontier NXDOMAIN hijack
    "198.105.254.11",    # Search Guide / Frontier NXDOMAIN hijack
    "198.105.254.130",   # Search Guide hijack
    "92.242.132.15",     # Barefruit NXDOMAIN hijack
    "92.242.132.16",     # Barefruit NXDOMAIN hijack
    "92.242.140.21",     # Barefruit NXDOMAIN hijack
    "34.102.136.180",    # Google Cloud Parking sinkhole
    "185.53.179.29",     # Sedo Domain Parking
    "185.53.178.29",     # Sedo Domain Parking
    "91.195.240.126",    # Bodis Domain Parking
    "103.224.182.244",   # Trellian / Above Parking
    "103.224.182.245",   # Trellian / Above Parking
}


def sanitize_domain_input(raw_input: str) -> str:
    """
    Cleans raw user input by stripping protocols, ports, paths, and trailing dots/slashes.
    Example: 'https://Sub.Domain.EDU.YE:8080/path?id=1#sec' -> 'sub.domain.edu.ye'
    """
    if not raw_input or not isinstance(raw_input, str):
        raise TargetValidationError("يرجى إدخال اسم نطاق صحيح، القيمة المدخلة فارغة.")

    clean = raw_input.strip().lower()

    # If scheme is missing, urlparse might place domain in path
    if "://" not in clean and not clean.startswith("//"):
        clean = "http://" + clean

    try:
        parsed = urlparse(clean)
        netloc = parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        netloc = clean

    # Strip userinfo (user:pass@domain) if present
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    # Strip port number
    if ":" in netloc:
        netloc = netloc.split(":", 1)[0]

    # Strip any stray slashes or dots
    netloc = netloc.strip().strip("./\\")

    # Handle Internationalized Domain Names (IDN / Arabic / Punycode)
    try:
        netloc = netloc.encode("idna").decode("ascii")
    except Exception:
        pass

    if not netloc:
        raise TargetValidationError("فشل استخراج اسم النطاق من القيمة المدخلة.")

    return netloc


def validate_domain_syntax(domain: str) -> None:
    """
    Verifies that the domain adheres to RFC 1035 and RFC 1123 standards:
    - Overall length between 3 and 253 characters.
    - Contains at least one dot.
    - Labels are 1-63 chars with valid alphanumeric and hyphen characters.
    - Top-Level Domain (TLD) has valid format (at least 2 alphabetic chars or punycode).
    """
    if len(domain) < 3:
        raise TargetValidationError(f"اسم النطاق '{domain}' قصير جداً وغير مكتمل.")

    if len(domain) > 253:
        raise TargetValidationError(f"اسم النطاق يتجاوز الحد الأقصى المسموح به عالمياً (253 حرفاً).")

    if "." not in domain:
        raise TargetValidationError(
            f"النطاق '{domain}' غير صالح؛ يجب أن يشتمل على امتداد TLD حقيقي (مثل: example.com أو target.edu.ye)."
        )

    # Check for consecutive dots
    if ".." in domain:
        raise TargetValidationError(f"تنسيق النطاق غير صالح: يحتوي على نقاط متتالية (..).")

    labels = domain.split(".")
    if len(labels) < 2:
        raise TargetValidationError(f"يجب أن يتكون النطاق من اسم وامتداد على الأقل.")

    # Validate each label
    for idx, label in enumerate(labels):
        if not label:
            raise TargetValidationError(f"تنسيق النطاق غير صالح: يحتوي على جزء فارغ بين النقاط.")

        if len(label) > 63:
            raise TargetValidationError(f"الجزء '{label}' في النطاق يتجاوز 63 حرفاً المسموح بها كحد أقصى.")

        if not LABEL_REGEX.match(label):
            raise TargetValidationError(
                f"الجزء '{label}' غير صالح؛ يُسمح فقط بالأحرف الإنجليزية والأرقام والشرطة (-) بشرط ألا تكون في البداية أو النهاية."
            )

    # Validate Top-Level Domain (last label)
    tld = labels[-1].lower()

    # Reject purely numeric TLDs (e.g. IPs masquerading as domains without 4 octets)
    if tld.isdigit():
        raise TargetValidationError(f"امتداد النطاق (TLD) '{tld}' غير صالح؛ لا يمكن أن يتكون من أرقام فقط.")

    # Check TLD minimum length and character set (must be >= 2 letters, or punycode xn--)
    if not (tld.startswith("xn--") or (len(tld) >= 2 and tld.isalpha())):
        raise TargetValidationError(
            f"امتداد النطاق '{tld}' غير صالح. يرجى استخدام امتداد دولي معتمد (مثل .com, .ye, .org, .net)."
        )

    # Reject blocked local/pseudo TLDs
    if tld in BLOCKED_PSEUDO_TLDS:
        raise TargetValidationError(
            f"الامتداد '.{tld}' هو نطاق محلي/داخلي خاص، ولا يمكن فحصه عبر المنظومة السحابية."
        )


def resolve_and_validate_dns(
    domain: str,
    timeout: float = 3.5,
    allow_private: bool = False
) -> List[str]:
    """
    Performs active DNS resolution to verify that the domain exists on the public internet
    with valid A or AAAA records.
    
    Guards against:
    - Non-existent domains (NXDOMAIN / gaierror).
    - Sinkhole & DNS parking IPs (0.0.0.0, 127.0.53.53).
    - Loopback and local network addresses (127.0.0.1, ::1) to prevent SSRF.
    - Private addresses (RFC 1918) unless explicitly permitted.
    """
    def _do_resolve():
        return socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

    # Enforce strict resolution timeout to protect worker threads
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_resolve)
            addr_info = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise TargetValidationError(
            f"استغرقت عملية التحقق من استجابة خوادم DNS للنطاق '{domain}' وقتاً أطول من المسموح ({timeout}s). يرجى التأكد من استقرار الخوادم."
        )
    except socket.gaierror as gai:
        raise TargetValidationError(
            f"فشل التحقق من النطاق '{domain}': النطاق غير مسجل أو لا يمتلك سجلات DNS نشطة (A/AAAA) على شبكة الإنترنت. تفاصيل: {gai.strerror or 'Host not found'}"
        )
    except Exception as exc:
        raise TargetValidationError(
            f"تعذر حل اسم النطاق '{domain}' عبر نظام DNS: {str(exc)}"
        )

    resolved_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        raise TargetValidationError(
            f"لم يتم العثور على أي عناوين IP نشطة (A/AAAA) مرتبطة بالنطاق '{domain}'."
        )

    # Validate resolved IP addresses for security compliance (SSRF & Sinkhole prevention)
    for ip_str in resolved_ips:
        if ip_str in SINKHOLE_IPS:
            raise TargetValidationError(
                f"النطاق '{domain}' يشير إلى عنوان محجوز/وهمي ({ip_str}) تابع لصفحات النطاقات المحجوزة أو غير المكتملة (Sinkhole/Parking)."
            )

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if ip_obj.is_loopback:
            raise TargetValidationError(
                f"النطاق '{domain}' يشير إلى عنوان محلي Loopback ({ip_str})؛ يُمنع فحصه منعاً لهجمات SSRF."
            )

        if ip_obj.is_unspecified:
            raise TargetValidationError(
                f"النطاق '{domain}' يشير إلى عنوان غير محدد ({ip_str})."
            )

        if not allow_private and ip_obj.is_private:
            raise TargetValidationError(
                f"النطاق '{domain}' يشير إلى عنوان شبكة داخلية خاصة ({ip_str})، وهي غير متاحة للفحص الخارجي."
            )

        if ip_obj.is_reserved or ip_obj.is_multicast:
            raise TargetValidationError(
                f"النطاق '{domain}' يشير إلى عنوان محجوز أو للبث المتعدد ({ip_str})."
            )

    # Check for wildcard DNS parking / ISP hijacking
    is_wildcard, wc_ip = check_wildcard_dns(domain, timeout=2.0)
    if is_wildcard and wc_ip:
        if wc_ip in SINKHOLE_IPS:
            raise TargetValidationError(
                f"النطاق '{domain}' هو نطاق حجز وهمي (Parked/Wildcard Domain) يوجه جميع الطلبات إلى خادم إعلانات/حجز ({wc_ip})."
            )
        try:
            wc_obj = ipaddress.ip_address(wc_ip)
            if wc_obj.is_loopback or wc_obj.is_private:
                raise TargetValidationError(
                    f"النطاق '{domain}' يوجه النطاقات الفرعية العشوائية لعنوان محلي/خاص ({wc_ip})."
                )
        except ValueError:
            pass

    return resolved_ips


def check_wildcard_dns(domain: str, timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """
    Probes a randomized non-existent subdomain to verify if the domain employs
    a wildcard DNS catch-all record (*.domain) or ISP NXDOMAIN hijack.
    """
    probe_host = f"ys-wc-{uuid.uuid4().hex[:12]}.{domain}"
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(
                socket.getaddrinfo,
                probe_host,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM
            )
            res = future.result(timeout=timeout)
            if res:
                wildcard_ip = res[0][4][0]
                return True, wildcard_ip
    except Exception:
        pass
    return False, None


def validate_target_domain(
    raw_input: str,
    check_dns: bool = True,
    allow_private: bool = False
) -> Tuple[str, List[str]]:
    """
    Main validation pipeline.
    Sanitizes domain input, validates RFC syntax and TLD, and performs live DNS lookup.
    
    :param raw_input: Raw domain input from user (e.g. 'https://ust.edu.ye/')
    :param check_dns: Whether to perform live DNS resolution (default True)
    :param allow_private: Whether to allow private IP targets (default False)
    :return: Tuple of (clean_domain, list_of_resolved_ips)
    :raises: TargetValidationError if domain is invalid or unresolvable
    """
    clean_domain = sanitize_domain_input(raw_input)
    validate_domain_syntax(clean_domain)

    resolved_ips: List[str] = []
    if check_dns:
        resolved_ips = resolve_and_validate_dns(
            clean_domain,
            timeout=4.0,
            allow_private=allow_private
        )

    return clean_domain, resolved_ips
