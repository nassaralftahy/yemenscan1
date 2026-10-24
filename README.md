# 🛡️ YemenScan (منظومة الفحص الأمني السحابي وإدارة سطح الهجوم)
### مشروع تخرج: منصة استطلاع وفحص أمني شامل لتطبيقات الويب وواجهات البرمجة (Black-box Attack Surface Management & DAST)

---

## 📌 نبذة عامة عن المشروع
منصة **YemenScan** هي مشروع تخرج أمني متكامل يهدف إلى أتمتة عمليات استكشاف الأصول الرقمية (Asset Discovery) وإدارة سطح الهجوم (Attack Surface Management) وإجراء الفحص الأمني للثغرات من منظور الصندوق الأسود (Black-box Assessment). 

تعتمد المنصة على خط إنتاج ذكي (Pipeline) يربط 6 أدوات قياسية عالمية عبر ثلاث مراحل رئيسية متسلسلة وفق المعايير الأكاديمية والأمنية المعتمدة عالمياً (**OWASP Web Top 10** و **OWASP API Security Top 10** و **CVEs**).

---

## 🏗️ المعمارية الهندسية ومراحل خط الفحص (The 3 Phases)

### 🔹 المرحلة الأولى: الاستكشاف وفحص المنافذ (Discovery & Port Scanning)
1. **Subfinder**:
   * **الدور**: استكشاف النطاقات الفرعية (Subdomains) المرتبطة بالنطاق الأساسي عبر مصادر سلبية (Passive OSINT Sources) دون إرسال حركة مرور مباشرة للهدف.
   * **المخرجات**: `subdomains.txt`.
2. **Naabu**:
   * **الدور**: استلام النطاقات الفرعية وإجراء فحص سريع لكافة المنافذ المفتوحة القياسية وغير القياسية (`80`, `443`, `8080`, `8443`, `8000`, `8888`, `3000`, إلخ) بمعدل طلبات آمن يمنع حجب الخدمة.
   * **المخرجات**: `ports.txt` (بتنسيق `host:port`).

---

### 🔹 المرحلة الثانية: تحديد خدمات الويب واستكشاف الـ APIs (Web & API Probing)
3. **HTTPX**:
   * **الدور**: التحقق من المنافذ المفتوحة النشطة التي تشغل خوادم ويب حية (HTTP/HTTPS Probing)، واستخراج بصمات التقنيات (Technologies)، خوادم الويب (Web Servers)، أكواد الحالة (Status Codes)، وعناوين الصفحات (Titles).
   * **المخرجات**: `active_urls.txt` و `active_urls.json`.
4. **Kiterunner**:
   * **الدور**: استهداف خوادم الويب الحية للكشف عن واجهات برمجة التطبيقات المخفية (Hidden APIs)، ومسارات التوثيق (Swagger / OpenAPI / API Docs / GraphQL)، ونقاط النهاية الحساسة.
   * **المخرجات**: `api_endpoints.txt` و `api_endpoints.json`.

---

### 🔹 المرحلة الثالثة: فحص الثغرات الأمنية (Vulnerability Scanning)
5. **Nuclei**:
   * **الدور**: فحص قوالبي سريع ومستهدف يستهدف الروابط ومسارات الـ APIs لاصطياد الثغرات المنشورة (Known CVEs)، وسوء الإعدادات (Security Misconfigurations)، وثغرات **OWASP API Top 10** مع فلترة مستويات الخطورة (Critical, High, Medium, Low).
   * **المخرجات**: `nuclei_findings.json`.
6. **Wapiti (DAST Engine)**:
   * **الدور**: فحص ديناميكي سلوكي لتطبيقات الويب المستهدفة يحاكي هجمات الويب الحقيقية وفق معايير **OWASP Web Top 10** (مثل: SQL Injection, XSS, Missing Security Headers, Cookie Security, Clickjacking).
   * **المخرجات**: `wapiti_findings.json`.
7. **Unified Vulnerability Normalizer**:
   * **الدور**: دمج وتنسيق الثغرات المكتشفة من المحركين في هيكل موحد مصنف حسب درجة الخطورة وتقديم توصيات إصلاح فنية واضحة لمدير النظام.
   * **المخرجات**: `unified_vulnerabilities.json`.

---

## 📂 هيكل ملفات المشروع (Project Structure)

```text
yemenscan1/
├── core/
│   ├── __init__.py
│   ├── session.py            # إدارة جلسات الفحص وحفظ السجلات
│   ├── runner.py             # مشغل الأوامر والحاويات الآمن
│   ├── stage1_discovery.py   # المرحلة 1: Subfinder + Naabu
│   ├── stage2_web_probing.py # المرحلة 2: HTTPX + Kiterunner API Probing
│   ├── stage3_vulnerabilities.py # المرحلة 3: Nuclei + Wapiti DAST
│   └── pipeline.py           # المنسق الشامل لخط الفحص
├── templates/
│   └── index.html            # لوحة التحكم التفاعلية المخصصة للمناقشة
├── scans/                    # مجلد معزول لكل جلسة فحص (scans/{scan_id}/)
├── main.py                   # تطبيق FastAPI والـ REST Endpoints
├── requirements.txt          # المتطلبات والمكتبات
└── README.md                 # وثيقة المشروع الأكاديمية
```

---

## 🚀 طريقة التثبيت والتشغيل

### 1. تثبيت المتطلبات البرمجية
```bash
pip install -r requirements.txt
```

### 2. تشغيل الخادم ولوحة التحكم
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

بعد التشغيل، افتح المتصفح على الرابط:
🔗 **http://127.0.0.1:8000**

---

## 📡 واجهات الـ REST API الرئيسية
 
| المسار (Endpoint) | الطريقة (Method) | الوصف |
|---|---|---|
| `/` | `GET` | لوحة التحكم التفاعلية الرسومية (Web Dashboard) |
| `/api/scan/start` | `POST` | بدء عملية فحص أمني شاملة بنطاق محدد |
| `/api/scan/stop` أو `/api/scan/{scan_id}/stop` | `POST` | إيقاف عملية الفحص الجارية فوراً وإنهاء الحاويات والعمليات |
| `/api/scan/{scan_id}/status` | `GET` | الاستعلام اللحظي عن حالة الفحص ونسبة التقدم ومصفوفة السجلات |
| `/api/scan/{scan_id}/discovery` | `GET` | نتائج المرحلة الأولى: النطاقات الفرعية والمنافذ النشطة |
| `/api/scan/{scan_id}/endpoints` | `GET` | نتائج المرحلة الثانية: روابط الويب ومسارات الـ APIs المكتشفة |
| `/api/scan/{scan_id}/vulnerabilities` | `GET` | نتائج المرحلة الثالثة: تقرير الثغرات الموحد (Nuclei + Wapiti) |
| `/api/scan/{scan_id}/ai-report` | `GET` | توليد التقرير الأمني الاستشاري بالذكاء الاصطناعي (Gemini AI: تنفيذي / تقني) |
| `/api/nuclei/info` | `GET` | حالة محرك Nuclei وتفصيل القوالب الـ 40 حسب الفئات التقنية |
| `/api/nuclei/scan` | `POST` | فحص فوري وموجه لرابط أو مسار محدد بقالب مخصص |
| `/api/scan/{scan_id}/report` | `GET` | التقرير التنفيذي المتكامل بصيغة JSON |
| `/api/scans` | `GET` | استرجاع قائمة بجميع عمليات الفحص السابقة وتفاصيلها |

---

## ⚖️ إخلاء المسؤولية وأخلاقيات الاستخدام (Ethical Scope)
تم تصميم هذه المنظومة لأغراض البحث الأكاديمي واختبار الاختراق الأخلاقي المصرح به فقط. يجب عدم فحص أو استهداف أي أنظمة أو شبكات دون الحصول على إذن مسبق ومكتوب من الجهة المالكة للأصل.
