# VVC Attendance & HRM - React Admin Panel v2.0

ប្រព័ន្ធគ្រប់គ្រងវត្តមាន និងធនធានមនុស្ស (Admin Portal) ទំនើប បង្កើតឡើងដោយ **React + Vite + TypeScript** ដោយរក្សាទុកនូវ UI Design ដើម ១០០% និងដំណើរការជាមួយ PHP REST API (`api.php`)។

---

## 🚀 របៀបដំណើរការ Local Development

1. ចូលទៅកាន់ Folder `admin_panel`៖
   ```bash
   cd admin_panel
   ```

2. ដំណើរការ Dev Server៖
   ```bash
   npm run dev
   ```
   * កម្មវិធីនឹងដំណើរការលើ `http://localhost:5173`
   * API Proxy ត្រូវបានកំណត់ដោយស្វ័យប្រវត្តទៅកាន់ `http://localhost/Vvc-Attendace/api.php`

---

## 📦 របៀប Build សម្រាប់ Hosting / Production

1. បង្កើត Production Bundle៖
   ```bash
   npm run build
   ```

2. ឯកសារដែល Build រួចនឹងស្ថិតនៅក្នុង `admin_panel/dist/`៖
   * លោកអ្នកអាចចម្លង file ទាំងអស់ក្នុង `dist/` ទៅដាក់ក្នុង Folder `public_html/admin/` ឬ Hosting ណាមួយក៏បាន។

---

## 🌟 លក្ខណៈពិសេសចម្បងៗ (Key Features)

* **ល្បឿន 0ms Page Switch**៖ ប្តូរទំព័រភ្លាមៗដោយគ្មាន White Flash ឬ Reload ទំព័រ។
* **UI Design ដើម ១០០%**៖ Kantumruy Pro font, Dark/Light Mode, Theme Colors, Tables, StatCards, Modals។
* **គ្រប់គ្រងបុគ្គលិក (Employees Management)**៖ ស្វែងរក Filter បង្កើត កែប្រែ និងលុបបុគ្គលិក។
* **របាយការណ៍វត្តមាន (Attendance Reports)**៖ Filter តាមថ្ងៃ សាខា ស្ថានភាព និង Export CSV។
* **អនុម័តសំណើរ (Requests Approval)**៖ ច្បាប់ឈប់សម្រាក, ថែមម៉ោង OT, បេសកកម្ម, ភ្លេចស្កេន ជាមួយ Approve/Reject។
* **ប្រាក់បៀវត្ស (Payroll)**៖ គណនាប្រាក់ខែគោល OT កាត់កង និងចេញ Payslip។
* **កិច្ចប្រជុំ & AI Summaries**៖ ស្តាប់សំឡេង HD និងមើលសេចក្តីសង្ខេប AI។
* **ការជូនដំណឹង (Push Notifications)**៖ ផ្ញើសារ Push ទៅកាន់ App ទូរស័ព្ទ។
* **ទីតាំង & QR Codes**៖ បង្កើតទីតាំង GPS និង QR Code Generator។
