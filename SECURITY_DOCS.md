# ឯកសារបច្ចេកទេសប្រព័ន្ធសុវត្ថិភាព VVC Security Guard WAF
> **VVC Attendance & HRM — Web Application Firewall & Threat Defense System**
> ឯកសារនេះពិពណ៌នាលម្អិតអំពីកូដ មុខងារ (Functions) និងយន្តការការពារសុវត្ថិភាពទាំងអស់ដែលមាននៅក្នុងឯកសារ `security_guard.php` ជាភាសាខ្មែរ។

---

## 📑 មាតិកា (Table of Contents)

1. [ទិដ្ឋភាពទូទៅនៃប្រព័ន្ធសុវត្ថិភាព (Overview)](#១-ទិដ្ឋភាពទូទៅនៃប្រព័ន្ធសុវត្ថិភាព)
2. [ផ្នែកទី ១: Security Headers & HTTPS Enforcement](#ផ្នែកទី-១-security-headers--https-enforcement)
3. [ផ្នែកទី ២: Client IP Resolver (`security_get_client_ip`)](#ផ្នែកទី-២-client-ip-resolver)
4. [ផ្នែកទី ៣: Threat Audit Logger (`security_log_threat`)](#ផ្នែកទី-៣-threat-audit-logger)
5. [ផ្នែកទី ៤: SQL Injection (SQLi) Defense (`security_inspect_sqli`)](#ផ្នែកទី-៤-sql-injection-sqli-defense)
6. [ផ្នែកទី ៥: Cross-Site Scripting (XSS) Sanitizer (`security_clean_xss`, `safe_html`)](#ផ្នែកទី-៥-cross-site-scripting-xss-sanitizer)
7. [ផ្នែកទី ៦: Brute Force & Rate Limiter (`security_check_login_throttle`, `security_record_login_result`)](#ផ្នែកទី-៦-brute-force--rate-limiter)
8. [ផ្នែកទី ៧: RCE & File Upload Armor (`security_validate_upload`)](#ផ្នែកទី-៧-rce--file-upload-armor)
9. [ផ្នែកទី ៨: Server-Side Request Forgery (SSRF) Guard (`security_is_safe_url`, `security_safe_curl`)](#ផ្នែកទី-៨-server-side-request-forgery-ssrf-guard)
10. [ផ្នែកទី ៩: Cross-Site Request Forgery (CSRF) Guard (`security_get_csrf_token`, `security_validate_csrf`)](#ផ្នែកទី-៩-cross-site-request-forgery-csrf-guard)
11. [ផ្នែកទី ១០: Broken Access Control & IDOR Guard (`security_check_ownership`)](#ផ្នែកទី-១០-broken-access-control--idor-guard)
12. [ផ្នែកទី ១១: Link & URL Attack Defense (`security_inspect_url_attacks`, `security_validate_redirect_url`, `safe_url`)](#ផ្នែកទី-១១-link--url-attack-defense)

---

## ១. ទិដ្ឋភាពទូទៅនៃប្រព័ន្ធសុវត្ថិភាព

`security_guard.php` គឺជាម៉ាស៊ីនការពារកម្រិត WAF (Web Application Firewall) ប្រចាំប្រព័ន្ធ VVC Attendance & HRM។ រាល់សំណើ Request (ទាំងពី Web Admin Panel និង Mobile App) ត្រូវឆ្លងកាត់ការស្កេន និងត្រួតពិនិត្យដោយស្វ័យប្រវត្តិកម្រិត Real-time ដើម្បីទប់ស្កាត់ការវាយប្រហារតាមអ៊ីនធឺណិតគ្រប់ទម្រង់ស្របតាមស្តង់ដារ **OWASP Top 10**។

---

## ផ្នែកទី ១: Security Headers & HTTPS Enforcement

### 🎯 គោលបំណងការពារ
ការពារការលួចស្ទាក់ចាប់ទិន្នន័យ (Man-In-The-Middle / MitM), ការបង្កប់ Frame បោកបញ្ឆោត (Clickjacking), និងការក្លែងបន្លំ MIME-type។

### ⚙️ កូដ និង Headers ដែលបានកំណត់
```php
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(self), camera=(self), microphone=()
session.cookie_samesite = Strict
session.cookie_httponly = 1
```

* **HSTS (`Strict-Transport-Security`)**៖ បង្ខំឱ្យ Browser តភ្ជាប់តែតាម `https://` សុវត្ថិភាពប៉ុណ្ណោះរយៈពេល 1 ឆ្នាំ។
* **`X-Frame-Options: SAMEORIGIN`**៖ រារាំងគេហទំព័រផ្សេងមិនឱ្យយក Web របស់យើងទៅបង្កប់ក្នុង `<iframe>` ដើម្បីលួច Click ឬលួចលេខសម្ងាត់ (Clickjacking)។
* **`X-Content-Type-Options: nosniff`**៖ បិទមិនឱ្យ Browser បកស្រាយ File ផ្តេសផ្តាស (ឧ. បកស្រាយរូបភាពជារូបរាង Script កូដ)។
* **`Cookie SameSite=Strict & HttpOnly`**៖ បិទមិនឱ្យ JavaScript អាចលួចអាន Cookie/Session ID បានឡើយ។

---

## ផ្នែកទី ២: Client IP Resolver

### 🎯 មុខងារ៖ `security_get_client_ip(): string`
* **តួនាទី**៖ ស្វែងរក និងចាប់យកអាសយដ្ឋាន IP ពិតប្រាកដរបស់ User ឬ Hacker ទោះបីជាពួកគេប្រើប្រាស់ Proxy, VPN, ឬ Cloudflare ក៏ដោយ។
* **លំដាប់នៃការចាប់ IP**៖
  1. `HTTP_CF_CONNECTING_IP` (Cloudflare Real IP)
  2. `HTTP_X_FORWARDED_FOR` (Load Balancer / Reverse Proxy IP)
  3. `HTTP_CLIENT_IP`
  4. `REMOTE_ADDR`
* **ការត្រួតពិនិត្យសុវត្ថិភាព**៖ ប្រើ `FILTER_VALIDATE_IP` ដើម្បីធានាថា IP ដែលទទួលបានមិនមែនជាកូដក្លែងបន្លំ (IP Header Injection)។

---

## ផ្នែកទី ៣: Threat Audit Logger

### 🎯 មុខងារ៖ `security_log_threat(string $threatType, string $details, string $severity): void`
* **តួនាទី**៖ កត់ត្រារាល់សកម្មភាពវាយប្រហារចូលទៅក្នុងតារាងទិន្នន័យ `audit_logs` ភ្លាមៗ។
* **ព័ត៌មានដែលកត់ត្រា**៖
  - ប្រភេទនៃការវាយប្រហារ (ឧ. `SQLI_BLOCKED`, `RCE_UPLOAD_BLOCKED`, `BRUTE_FORCE_LOCKOUT`)
  - កម្រិតគ្រោះថ្នាក់ (`critical`, `warning`, `danger`)
  - អាសយដ្ឋាន IP របស់ជនវាយប្រហារ
  - URL និង Parameter ដែលជនវាយប្រហារបានផ្ញើមក
  - ប្រភេទ Browser & OS (User Agent)
  - ពេលវេលាជាក់ស្តែង (Timestamp)

---

## ផ្នែកទី ៤: SQL Injection (SQLi) Defense

### 🎯 មុខងារ៖ `security_inspect_sqli($data, $keyPath = ''): void`
* **តួនាទី**៖ ស្កេនពិនិត្យរាល់ទិន្នន័យក្នុង `$_GET`, `$_POST`, និង JSON Request ទាំងអស់ជាទម្រង់ Recursive (គ្រប់ជាន់)។
* **លំនាំកូដវាយប្រហារ (Attack Signatures) ដែលប្រព័ន្ធស្ទាក់ និង Block**៖
  - `UNION SELECT`, `UNION ALL SELECT`
  - `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY` (Time-based Blind SQLi)
  - `INFORMATION_SCHEMA.TABLES`, `INFORMATION_SCHEMA.COLUMNS`
  - `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE()`
  - `XP_CMDSHELL`, `SP_EXECUTESQL`
  - `OR '1'='1'`, `OR 1=1`, `AND 1=1`, Stacked quotes (`--`, `/* */`, `#`)
* **វិធានការពេលរកឃើញ**៖ បញ្ឈប់ដំណើរការភ្លាមៗ បញ្ជូន `HTTP 403 Forbidden` + កត់ត្រាចូល Audit Log។

---

## ផ្នែកទី ៥: Cross-Site Scripting (XSS) Sanitizer

### 🎯 មុខងារ៖ `security_clean_xss($data)` & `safe_html($str)`
* **តួនាទី**៖ លុបបំបាត់រាល់កូដ Script និង Event Handlers គ្រោះថ្នាក់ចេញពីទិន្នន័យ Input ទាំងអស់មុនពេលយកទៅប្រើប្រាស់។
* **Tag និង Attribute ដែលត្រូវលុបចេញស្វ័យប្រវត្តិ**៖
  - `<script>...</script>`
  - `javascript:...`, `vbscript:...`
  - `onerror=...`, `onload=...`, `onclick=...`, `onmouseover=...`
  - `<iframe>`, `<object>`, `<embed>`, `<svg onload=...>`
* **មុខងារ `safe_html($str)`**៖ ប្រើ `htmlspecialchars($str, ENT_QUOTES | ENT_HTML5, 'UTF-8')` ដើម្បីបម្លែងតួអក្សរពិសេស (`<`, `>`, `"`, `'`, `&`) ទៅជា HTML Entities សុវត្ថិភាព ១០០% មុនពេល Render លើអេក្រង់។

---

## ផ្នែកទី ៦: Brute Force & Rate Limiter

### 🎯 មុខងារ៖ `security_check_login_throttle($username)` & `security_record_login_result($username, $success)`
* **តួនាទី**៖ ការពារការទាយលេខសម្ងាត់ដោយស្វ័យប្រវត្តិតាមរយៈ Bot ឬ Hacker (Credential Stuffing / Dictionary Attack)។
* **យន្តការការពារ**៖
  1. តាមដានចំនួនប៉ុនប៉ង Login តាមរយៈគូ `IP Address + Username` ក្នុងតារាង `security_rate_limits`។
  2. ប្រសិនបើ Login ខុសដល់ **៥ ដង** នោះប្រព័ន្ធនឹង **ចាក់សោរ (Lockout) រយៈពេល ១៥ នាទី**។
  3. ពេលជាប់សោរ ប្រព័ន្ធនឹងបញ្ជូនកូដ `HTTP 429 Too Many Requests` រួមជាមួយសារប្រាប់ចំនួននាទីដែលនៅសល់។
  4. នៅពេល Login ជោគជ័យ ចំនួនរាប់ខុសនឹងត្រូវ Reset ទៅសូន្យវិញភ្លាមៗ។

---

## ផ្នែកទី ៧: RCE & File Upload Armor

### 🎯 មុខងារ៖ `security_validate_upload(array $file, array $allowedExtensions, int $maxSizeBytes): array`
* **តួនាទី**៖ ទប់ស្កាត់ការ Upload ឯកសារមេរោគ Web Shell ឬកូដ Script ដើម្បីគ្រប់គ្រង Server (Remote Code Execution)។
* **យន្តការការពារ ៤ ជាន់**៖
  1. **Extension Blacklist Check**៖ បិទដាច់ខាតប្រភេទ `.php`, `.phtml`, `.exe`, `.py`, `.sh`, `.bat`, `.htaccess`, `.env`, `.ini`។
  2. **Extension Whitelist Check**៖ អនុញ្ញាតតែប្រភេទរូបភាព និងឯកសារចាំបាច់ (ឧ. `.jpg`, `.png`, `.webp`, `.pdf`, `.mp3`, `.mp4`)។
  3. **Deep Content Inspection**៖ អានពិនិត្យមាតិកាខាងក្នុងឯកសារ ហាមដាច់ខាតការបង្កប់ PHP Code (`<?php`, `<?=`, `eval()`, `base64_decode()`, `system()`) ក្នុងរូបភាព។
  4. **Random Hashed Filename**៖ ប្តូរឈ្មោះ File ទៅជា Random Hash 32 តួអក្សរ (`bin2hex(random_bytes(16)) . '_' . time() . '.' . $ext`) ដើម្បីកុំឱ្យ Hacker ដឹងពីទីតាំងពិតនៃ File។

---

## ផ្នែកទី ៨: Server-Side Request Forgery (SSRF) Guard

### 🎯 មុខងារ៖ `security_is_safe_url(string $url): bool` & `security_safe_curl(string $url, array $options): array`
* **តួនាទី**៖ ទប់ស្កាត់ការបោកបញ្ឆោត Server ឱ្យទៅទាញយកទិន្នន័យពីបណ្តាញផ្ទៃក្នុង (Internal Network) ឬ Cloud Metadata។
* **អាសយដ្ឋានដែលត្រូវបានបិទ (Blocked Destinations)**៖
  - Localhost / Loopback (`127.0.0.1`, `::1`, `localhost`)
  - Cloud Metadata Services (`169.254.169.254`, `metadata.google.internal`)
  - Private IP Ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
* **`security_safe_curl()`**៖ បិទ `CURLOPT_FOLLOWLOCATION` ដើម្បីការពារ Redirect SSRF Bypass និងកំណត់ Timeout ច្បាស់លាស់។

---

## ផ្នែកទី ៩: Cross-Site Request Forgery (CSRF) Guard

### 🎯 មុខងារ៖ `security_get_csrf_token(): string` & `security_validate_csrf(): bool`
* **តួនាទី**៖ ការពារការលួចផ្ញើសំណើពីគេហទំព័រផ្សេងដោយគ្មានការអនុញ្ញាតពីម្ចាស់គណនី (Cross-Site Forged Actions)។
* **យន្តការការពារ**៖
  - បង្កើត Token ដោយប្រើ `bin2hex(random_bytes(32))` ដែលមិនអាចទាយដឹងបាន។
  - ត្រួតពិនិត្យតាមរយៈ Header `X-CSRF-TOKEN` ឬ POST parameter `csrf_token` ជាមួយ `hash_equals()` ដើម្បីការពារ Timing Attacks។
  - លើកលែងដោយស្វ័យប្រវត្តិចំពោះសំណើដែលមាន `Authorization: Bearer <token>` សម្រាប់ Mobile App & REST Clients។

---

## ផ្នែកទី ១០: Broken Access Control & IDOR Guard

### 🎯 មុខងារ៖ `security_check_ownership(?string $role, ?string $actorId, ?string $targetId): bool`
* **តួនាទី**៖ ទប់ស្កាត់ការលួចកែប្រែ ID ក្នុង Parameter (Insecure Direct Object Reference / IDOR) ដើម្បីលួចមើល ឬកែទិន្នន័យអ្នកដទៃ។
* **គោលការណ៍ពិនិត្យសិទ្ធិ (RBAC Logic)**៖
  - ប្រសិនបើអ្នកប្រើជា `Superadmin`, `Admin`, ឬ `HR` -> អនុញ្ញាតឱ្យមើល និងកែសម្រួលទិន្នន័យបានទាំងអស់។
  - ប្រសិនបើអ្នកប្រើជាបុគ្គលិកធម្មតា (`Employee`) -> អនុញ្ញាតឱ្យមើល/កែសម្រួលតែលើទិន្នន័យដែលជាកម្មសិទ្ធិផ្ទាល់ខ្លួនប៉ុណ្ណោះ (`actorId === targetId`)។
  - ប្រសិនបើព្យាយាមចូលមើលទិន្នន័យអ្នកដទៃ -> ប្រព័ន្ធនឹងបដិសេធ និងកត់ត្រាការប៉ុនប៉ងចូល `audit_logs` កម្រិត `warning`។

---

## ផ្នែកទី ១១: Link & URL Attack Defense

### 🎯 មុខងារ៖ `security_inspect_url_attacks()`, `security_validate_redirect_url()`, `safe_url()`
* **តួនាទី**៖ ទប់ស្កាត់ការវាយប្រហារតាមរយៈ Links, Query Strings, Path Traversal, និង Open Redirect Phishing។

### ១. ស្កេន URL Traversal & System Files (`security_inspect_url_attacks()`)
- ដំណើរការស្វ័យប្រវត្តិលើរាល់ Request ដោយពិនិត្យ `REQUEST_URI`, `QUERY_STRING`, និង `PATH_INFO`។
- រារាំងដាច់ខាតទម្រង់៖
  - `../`, `..\`, `%2e%2e%2f`, `%252e%252e`
  - Null Byte `%00`, `\x00`
  - ឈ្មោះឯកសារប្រព័ន្ធសម្ងាត់៖ `etc/passwd`, `etc/shadow`, `win.ini`, `boot.ini`
  - ពាក្យបញ្ជា Server តាម URL៖ `cmd.exe`, `powershell`, `bin/sh`, `bin/bash`
- ប្រសិនបើរកឃើញ -> បញ្ជូន `HTTP 403 Forbidden` ភ្លាមៗ។

### ២. ការពារ Open Redirect Phishing (`security_validate_redirect_url($url)`)
- ពិនិត្យ Link គោលដៅមុនពេលបញ្ជូន User ទៅ (Redirect)។
- អនុញ្ញាតតែ Relative Paths (ឧ. `/dashboard`, `/reports`) ឬ Domains ក្រុមហ៊ុនដែលទុកចិត្ត (`app.vvc.asia`, `vvc.asia`, `kouprey.asia`, `sksk.asia`)។
- ប្រសិនបើជា Link ក្រៅពីនេះ វានឹងត្រូវប្តូរមកកាន់ទំព័រដើម `/` ដោយសុវត្ថិភាព។

### ៣. សម្អាត Link របស់អ្នកប្រើប្រាស់ (`safe_url($url)`)
- អនុញ្ញាតតែ Protocol សុវត្ថិភាព `https://`, `http://`, `mailto:`, `tel:`។
- លុបបំបាត់ដាច់ខាតនូវ Scheme គ្រោះថ្នាក់ `javascript:`, `data:`, `vbscript:`, `file:`។

---

## 📊 សង្ខេបតារាងមុខងារ និងកម្រិតការពារ

| មុខងារ (Function) | កិច្ចការពារ (Protection Domain) | កម្រិតឆ្លើយតប (Response) |
| :--- | :--- | :--- |
| **`security_inspect_sqli`** | SQL Injection លើ GET/POST/JSON | 403 Forbidden + Audit Log |
| **`security_clean_xss`** | Cross-Site Scripting (XSS) | លុប tags គ្រោះថ្នាក់ស្វ័យប្រវត្តិ |
| **`safe_html`** | HTML Output Encoding | `htmlspecialchars` UTF-8 |
| **`security_check_login_throttle`** | Brute Force Protection | 429 Too Many Requests (Lock 15 នាទី) |
| **`security_validate_upload`** | RCE & Web Shell Upload | បដិសេធ File + Magic Bytes Check + Rename |
| **`security_is_safe_url`** | SSRF & Internal IP Scan | Block Localhost / Private IPs / Cloud Metadata |
| **`security_validate_csrf`** | Cross-Site Request Forgery | Token Validation / Bearer Auth |
| **`security_check_ownership`** | Broken Access Control / IDOR | ពិនិត្យសិទ្ធិ Role & User ID |
| **`security_inspect_url_attacks`**| Path Traversal & URL Injection | 403 Forbidden + Threat Log |
| **`security_validate_redirect_url`**| Open Redirect Phishing | Domain Whitelisting |

---
*ឯកសារនេះត្រូវបានបង្កើតឡើងដោយស្វ័យប្រវត្តិសម្រាប់ជាឯកសារយោង និងការគ្រប់គ្រងប្រព័ន្ធសុវត្ថិភាព VVC Attendance & HRM។*
