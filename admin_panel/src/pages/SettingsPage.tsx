import React, { useState, useEffect } from 'react';
import {
  Settings,
  Save,
  Shield,
  Palette,
  Smartphone,
  Check,
  LayoutGrid,
  Menu,
  LogIn,
  Sliders,
  Send,
  Building,
  Box,
  Columns,
  History,
  Type,
  Eye,
  Trash2,
  ChevronUp,
  ChevronDown,
  GripVertical,
  RefreshCw,
} from 'lucide-react';
import { adminApi } from '../api/adminApi';

// All 25 Card definitions matching admin_attendance.php
const ALL_CARD_KEYS = [
  { key: 'stats_slider', label: 'ស្ថិតិ (Stats Slider)' },
  { key: 'attendance', label: 'ស្កេនវត្តមាន (Attendance)' },
  { key: 'outside_attendance', label: 'ស្កេនខាងក្រៅ (Outside Check-In)' },
  { key: 'kpi', label: 'ការវាយតម្លៃ KPI/OKR' },
  { key: 'product_analyzer', label: 'វិភាគផលិតផល (Product Analyzer)' },
  { key: 'training_quiz', label: 'វគ្គបណ្តុះបណ្តាល (Training Quiz)' },
  { key: 'poll_voting', label: 'បោះឆ្នោតបុគ្គលិក (Poll Voting)' },
  { key: 'announcements', label: 'ការជូនដំណឹង (News)' },
  { key: 'meetings', label: 'កិច្ចប្រជុំ (Meetings)' },
  { key: 'checklist', label: 'បញ្ជីការងារ (Checklist)' },
  { key: 'daily_report', label: 'របាយការណ៍ប្រចាំថ្ងៃ (Daily)' },
  { key: 'mission', label: 'លិខិតបេសកកម្ម (Mission)' },
  { key: 'trip', label: 'ការធ្វើដំណើរ (Trip Tracking)' },
  { key: 'user_management', label: 'គ្រប់គ្រងបុគ្គលិក (Users)' },
  { key: 'request_form', label: 'បញ្ជីសំណើ (Requests)' },
  { key: 'reports', label: 'របាយការណ៍វត្តមាន (Reports)' },
  { key: 'material_request', label: 'ស្នើសុំសម្ភារៈ (Materials)' },
  { key: 'notification', label: 'ផ្ញើការជូនដំណឹង (Notify)' },
  { key: 'notification_history', label: 'ប្រវត្តិជូនដំណឹង (Notify History)' },
  { key: 'employee_report', label: 'របាយការណ៍បុគ្គលិក (Employee Report)' },
  { key: 'payroll', label: 'ប្រាក់បៀវត្ស (Payroll)' },
  { key: 'document_scanner', label: 'ស្កេនឯកសារ (Document Scanner)' },
  { key: 'app_settings', label: 'ការកំណត់កម្មវិធី (App Settings)' },
  { key: 'profile_footer', label: 'Profile Footer' },
  { key: 'home_footer', label: 'Home Footer' },
];

// All Visibility Roles matching admin_attendance.php & enterprise_helpers.php
const VISIBILITY_ROLES = [
  { suffix: 'skill', label: 'បុគ្គលិក (Staff)', fullLabel: 'Visibility (បុគ្គលិក)', isWorker: false, showBranch: true },
  { suffix: 'worker', label: 'កម្មករ (Worker)', fullLabel: 'Visibility (កម្មករ)', isWorker: true, showBranch: false },
  { suffix: 'hrm', label: 'HRM', fullLabel: 'Visibility (HRM)', isWorker: false, showBranch: false },
  { suffix: 'admin', label: 'Admin', fullLabel: 'Visibility (Admin)', isWorker: false, showBranch: false },
  { suffix: 'store318_head', label: 'ប្រធានហាងទំនិញ 318', fullLabel: 'Visibility (ប្រធានហាងទំនិញ 318)', isWorker: false, showBranch: false },
  { suffix: 'store_skks2_head', label: 'ប្រធានហាង SKKS2', fullLabel: 'Visibility (ប្រធានហាង SKKS2)', isWorker: false, showBranch: false },
  { suffix: 'store_nr3_head', label: 'ប្រធានហាង NR3', fullLabel: 'Visibility (ប្រធានហាង NR3)', isWorker: false, showBranch: false },
  { suffix: 'store_skks2_deputy', label: 'អនុប្រធានហាង SKKS2', fullLabel: 'Visibility (អនុប្រធានហាង SKKS2)', isWorker: false, showBranch: false },
  { suffix: 'store_nr3_deputy', label: 'អនុប្រធានហាង NR3', fullLabel: 'Visibility (អនុប្រធានហាង NR3)', isWorker: false, showBranch: false },
  { suffix: 'warehouse_psp_head', label: 'ប្រធានឃ្លាំង PSP', fullLabel: 'Visibility (ប្រធានឃ្លាំង PSP)', isWorker: false, showBranch: false },
  { suffix: 'warehouse_prv_head', label: 'ប្រធានឃ្លាំង PRV', fullLabel: 'Visibility (ប្រធានឃ្លាំង PRV)', isWorker: false, showBranch: false },
  { suffix: 'warehouse_psp_assistant', label: 'ជំនួយការប្រធានឃ្លាំង PSP', fullLabel: 'Visibility (ជំនួយការប្រធានឃ្លាំង PSP)', isWorker: false, showBranch: false },
  { suffix: 'warehouse_prv_assistant', label: 'ជំនួយការប្រធានឃ្លាំង PRV', fullLabel: 'Visibility (ជំនួយការប្រធានឃ្លាំង PRV)', isWorker: false, showBranch: false },
  { suffix: 'stock_general_head', label: 'ប្រធានគ្រប់គ្រងស្តុកទំនិញទូទៅ', fullLabel: 'Visibility (ប្រធានគ្រប់គ្រងស្តុកទំនិញទូទៅ)', isWorker: false, showBranch: false },
  { suffix: 'general_manager_sk', label: 'ប្រធានគ្រប់គ្រងទូទៅ (SK)', fullLabel: 'Visibility (ប្រធានគ្រប់គ្រងទូទៅ (SK))', isWorker: false, showBranch: false },
  { suffix: 'general_manager_vvc', label: 'ប្រធានគ្រប់គ្រងទូទៅ (VVC)', fullLabel: 'Visibility (ប្រធានគ្រប់គ្រងទូទៅ (VVC))', isWorker: false, showBranch: false },
  { suffix: 'director_general', label: 'អគ្គនាយក', fullLabel: 'Visibility (អគ្គនាយក)', isWorker: false, showBranch: false },
];

// Seasonal Themes
const SEASONAL_THEMES = [
  { key: 'default', name: 'Default', desc: 'Professional Blue', color: '#6366f1', bg: '#f8fafc', text: '#ffffff' },
  { key: 'khmer_new_year', name: 'KNY', desc: 'Golden Khmer (ចូលឆ្នាំខ្មែរ)', color: '#FFD700', bg: '#fdfaea', text: '#8B4513' },
  { key: 'chinese_new_year', name: 'CNY', desc: 'Vibrant Red (ចូលឆ្នាំចិន)', color: '#e53e3e', bg: '#fff5f5', text: '#ffd700' },
  { key: 'pchum_ben', name: 'Pchum Ben', desc: 'Calm White (ភ្ជុំបិណ្ឌ)', color: '#94a3b8', bg: '#ffffff', text: '#1e293b' },
  { key: 'water_festival', name: 'Water', desc: 'Energetic Blue (អុំទូក)', color: '#0284c7', bg: '#f0f9ff', text: '#ffffff' },
  { key: 'bayon_spirit', name: 'Bayon', desc: 'Bayon Spirit (ស្មារតីបាយ័ន)', color: '#1F4B99', bg: '#e2e8f0', text: '#ffffff' },
  { key: 'angkor_empire', name: 'Empire', desc: 'Angkor Empire (អាណាចក្រអង្គរ)', color: '#D4AF37', bg: '#fefce8', text: '#ffffff' },
  { key: 'romduol_bloom', name: 'Romduol', desc: 'Romduol Bloom (បុប្ផារំដួល)', color: '#db2777', bg: '#fdf2f8', text: '#ffffff' },
  { key: 'silver_pagoda', name: 'Silver', desc: 'Silver Pagoda (ព្រះវិហារប្រាក់)', color: '#94a3b8', bg: '#f8fafc', text: '#ffffff' },
  { key: 'auto', name: 'Auto', desc: 'Auto (ប្តូរតាមកាលបរិច្ឆេទ)', color: '#10b981', bg: '#ecfdf5', text: '#ffffff' },
];

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<
    'panel_settings' | 'menu_settings' | 'login_page_settings' | 'theme_management' | 'manage_app_scan'
  >('panel_settings');

  // Sub-tabs inside Manage App Scan (All tabs matching screenshot)
  const [appScanSubTab, setAppScanSubTab] = useState<string>('branding');

  // Panel Settings state
  const [panelTitle, setPanelTitle] = useState('VVC ATTENDANCE');
  const [companyName, setCompanyName] = useState('VVC Asia Co., Ltd.');
  const [footerText, setFooterText] = useState('© 2026 VVC Asia Co., Ltd. All Rights Reserved.');

  // 1. Branding
  const [appDisplayName, setAppDisplayName] = useState('VVC ATTENDANCE');
  const [headerType, setHeaderType] = useState('title');
  const [headerTitle, setHeaderTitle] = useState('Attendance App');
  const [headerSubtitle, setHeaderSubtitle] = useState('');
  const [headerLogoPath, setHeaderLogoPath] = useState('');

  // 2. Version & Updates
  const [appVersion, setAppVersion] = useState('1.0.5');
  const [appBuild, setAppBuild] = useState('5');
  const [apkUrl, setApkUrl] = useState('https://app.vvc.asia/downloads/vvc_attendance.apk');
  const [updateMessage, setUpdateMessage] = useState('សូមធ្វើបច្ចុប្បន្នភាពកម្មវិធី ដើម្បីទទួលបានមុខងារថ្មីៗ!');
  const [forceUpdate, setForceUpdate] = useState(false);

  // 3. Security & Biometrics
  const [lateThreshold, setLateThreshold] = useState('15');
  const [requireFaceScan, setRequireFaceScan] = useState(true);
  const [allowOutsideScan, setAllowOutsideScan] = useState(false);
  const [payrollBiometric, setPayrollBiometric] = useState(true);
  const [payrollRecords, setPayrollRecords] = useState<any[]>([]);
  const [loadingBio, setLoadingBio] = useState(false);

  // 4. All Visibility Roles (Dynamic Maps)
  const [roleLayouts, setRoleLayouts] = useState<Record<string, string>>({});
  const [roleCards, setRoleCards] = useState<Record<string, Record<string, boolean>>>({});
  const [roleOrders, setRoleOrders] = useState<Record<string, string[]>>({});
  const [branchIds318, setBranchIds318] = useState('');
  const [branchIdsKs2, setBranchIdsKs2] = useState('');
  const [branchIdsNr3, setBranchIdsNr3] = useState('');

  // 5. Labels & Languages
  const [greetingMorning, setGreetingMorning] = useState('🌅 អរុណសួស្តី');
  const [greetingAfternoon, setGreetingAfternoon] = useState('☀️ ទិវាសួស្តី');
  const [greetingEvening, setGreetingEvening] = useState('🌙 សាយណ្ហសួស្តី');
  const [homeTitle, setHomeTitle] = useState('VVC EMPLOYEE PASS');
  const [labelAttendance, setLabelAttendance] = useState('ស្កេនវត្តមាន');
  const [labelRequest, setLabelRequest] = useState('សំណើផ្សេងៗ');
  const [appDefaultDarkMode, setAppDefaultDarkMode] = useState(true);

  // 6. Telegram Configuration
  const [tgBotToken, setTgBotToken] = useState('');
  const [tgChatId, setTgChatId] = useState('');
  const [tgNotifyAttendance, setTgNotifyAttendance] = useState(false);
  const [tgNotifyRequests, setTgNotifyRequests] = useState(false);
  const [tgTplAttendance, setTgTplAttendance] = useState(
    '<b>Name :</b> {{name}}\n<b>Status :</b> {{action}} ({{status}})\nReason : {{late_reason}}\n------------------------------------------\n<b>ID :</b> {{employee_id}}\n<b>Department :</b> {{field_department}}\n<b>Position :</b> {{field_position}}\n<b>Date/Time :</b> {{time}}\n<b>Area :</b> {{location_name}}\n<b>Distance :</b> {{distance_m}}m\n\n{{map_url}}'
  );
  const [tgTplRequest, setTgTplRequest] = useState('');
  const [showPreviewGenAtt, setShowPreviewGenAtt] = useState(false);

  const [tgBotTokenWorker, setTgBotTokenWorker] = useState('');
  const [tgChatIdWorker, setTgChatIdWorker] = useState('');
  const [tgNotifyAttendanceWorker, setTgNotifyAttendanceWorker] = useState(false);
  const [tgNotifyRequestsWorker, setTgNotifyRequestsWorker] = useState(false);
  const [tgTplAttendanceWorker, setTgTplAttendanceWorker] = useState('');
  const [tgTplRequestWorker, setTgTplRequestWorker] = useState('');

  const [tgTimeFormatPreset, setTgTimeFormatPreset] = useState('Y-m-d H:i:s');
  const [tgTimeFormat, setTgTimeFormat] = useState('Y-m-d H:i:s');

  const [reminderEnabled, setReminderEnabled] = useState(false);
  const [reminderMinutes, setReminderMinutes] = useState('10');
  const [reminderSound, setReminderSound] = useState('default');

  const [dailyReportEnabled, setDailyReportEnabled] = useState(false);
  const [dailyReportReporterId, setDailyReportReporterId] = useState('');
  const [dailyReportBotToken, setDailyReportBotToken] = useState('');
  const [dailyReportChatId, setDailyReportChatId] = useState('');
  const [dailyReportTemplate, setDailyReportTemplate] = useState('');

  // 7. Departments Whitelist
  const [allowedDeptSkill, setAllowedDeptSkill] = useState('');
  const [allowedDeptWorker, setAllowedDeptWorker] = useState('');

  // 8. Materials & Locations
  const [materialLocations, setMaterialLocations] = useState('Main Office (318), Factory 1 (NR3), Factory 2 (KS2)');

  // 9. Column Visibility
  const [colCheckbox, setColCheckbox] = useState(true);
  const [colEmpId, setColEmpId] = useState(true);
  const [colName, setColName] = useState(true);
  const [colAction, setColAction] = useState(true);
  const [colDate, setColDate] = useState(true);
  const [colTime, setColTime] = useState(true);
  const [colStatus, setColStatus] = useState(true);
  const [colLateReason, setColLateReason] = useState(true);
  const [colActions, setColActions] = useState(true);

  // 10. Seasonal Themes
  const [appThemeSeason, setAppThemeSeason] = useState('default');

  // 11. Scan History Logs
  const [scanLogs, setScanLogs] = useState<any[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);

  // Login Page Settings state
  const [loginTitle, setLoginTitle] = useState('VVC Attendance Portal');
  const [loginSubtitle, setLoginSubtitle] = useState('សូមបញ្ចូលគណនីរបស់អ្នកដើម្បី Login ចូលប្រើប្រាស់');
  const [loginLogo, setLoginLogo] = useState('');
  const [loginIcon, setLoginIcon] = useState('fa-solid fa-user-shield');

  // Menu Settings state
  const [menus, setMenus] = useState<any[]>([
    { key: 'dashboard', text: 'ផ្ទាំងគ្រប់គ្រង (Dashboard)', order: 1 },
    { key: 'attendance', text: 'របាយការណ៍វត្តមាន (Attendance)', order: 2 },
    { key: 'requests', text: 'គ្រប់គ្រងសំណើរ (Requests)', order: 3 },
    { key: 'locations', text: 'ទីតាំង & QR Codes (Locations)', order: 4 },
    { key: 'stock', text: 'គ្រប់គ្រងស្តុក (Stock Control)', order: 5 },
    { key: 'meetings', text: 'កិច្ចប្រជុំ & AI (Meetings)', order: 6 },
    { key: 'polls', text: 'ការបោះឆ្នោត (Polls & Voting)', order: 7 },
    { key: 'payroll', text: 'ប្រាក់បៀវត្ស (Payroll)', order: 8 },
    { key: 'tokens', text: 'សុវត្ថិភាព Session (Tokens)', order: 9 },
    { key: 'training', text: 'បណ្តុះបណ្តាល (Quiz)', order: 10 },
    { key: 'settings', text: 'ការកំណត់ប្រព័ន្ធ (Settings)', order: 11 },
  ]);

  // Themes state
  const [themes, setThemes] = useState<any[]>([]);
  const [activeThemeId, setActiveThemeId] = useState('default');

  // Status & feedback
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    loadAllSettings();
  }, []);

  const loadAllSettings = async () => {
    try {
      const panelRes = await adminApi.fetchSettings();
      if (panelRes && panelRes.settings) {
        const s = panelRes.settings;
        if (s.panel_title) setPanelTitle(s.panel_title);
        if (s.company_name) setCompanyName(s.company_name);
        if (s.footer_text) setFooterText(s.footer_text);
        if (s.app_display_name) setAppDisplayName(s.app_display_name);
        if (s.header_type) setHeaderType(s.header_type);
        if (s.header_title) setHeaderTitle(s.header_title);
        if (s.header_subtitle) setHeaderSubtitle(s.header_subtitle);
        if (s.header_logo_path) setHeaderLogoPath(s.header_logo_path);

        if (s.late_threshold_minutes) setLateThreshold(s.late_threshold_minutes);
        if (s.require_face_scan !== undefined) setRequireFaceScan(s.require_face_scan === '1');
        if (s.face_scan_enabled !== undefined) setRequireFaceScan(s.face_scan_enabled === '1');
        if (s.allow_outside_scan !== undefined) setAllowOutsideScan(s.allow_outside_scan === '1');
        if (s.payroll_biometric_required !== undefined) setPayrollBiometric(s.payroll_biometric_required === '1');

        if (s.app_latest_version) setAppVersion(s.app_latest_version);
        if (s.app_latest_build) setAppBuild(s.app_latest_build);
        if (s.app_apk_url) setApkUrl(s.app_apk_url);
        if (s.app_update_message) setUpdateMessage(s.app_update_message);
        if (s.app_force_update !== undefined) setForceUpdate(s.app_force_update === '1');

        if (s.employee_report_ids_318) setBranchIds318(s.employee_report_ids_318);
        if (s.employee_report_ids_ks2) setBranchIdsKs2(s.employee_report_ids_ks2);
        if (s.employee_report_ids_nr3) setBranchIdsNr3(s.employee_report_ids_nr3);

        // Load all visibility roles dynamically
        const layouts: Record<string, string> = {};
        const cardsMap: Record<string, Record<string, boolean>> = {};
        const ordersMap: Record<string, string[]> = {};

        VISIBILITY_ROLES.forEach((r) => {
          layouts[r.suffix] = s[`home_layout_type__${r.suffix}`] || 'grid';

          const cardObj: Record<string, boolean> = {};
          const defaultVisible = r.isWorker ? false : true;
          ALL_CARD_KEYS.forEach((c) => {
            const val = s[`show_${c.key}_card__${r.suffix}`];
            cardObj[c.key] = val !== undefined ? val === '1' : defaultVisible;
          });
          cardsMap[r.suffix] = cardObj;

          const orderStr = s[`home_card_order__${r.suffix}`];
          if (orderStr) {
            const arr = orderStr.split(',').filter(Boolean);
            ALL_CARD_KEYS.forEach((c) => {
              if (!arr.includes(c.key)) arr.push(c.key);
            });
            ordersMap[r.suffix] = arr;
          } else {
            ordersMap[r.suffix] = ALL_CARD_KEYS.map((c) => c.key);
          }
        });

        setRoleLayouts(layouts);
        setRoleCards(cardsMap);
        setRoleOrders(ordersMap);

        if (s.greeting_morning) setGreetingMorning(s.greeting_morning);
        if (s.greeting_afternoon) setGreetingAfternoon(s.greeting_afternoon);
        if (s.greeting_evening) setGreetingEvening(s.greeting_evening);
        if (s.home_title) setHomeTitle(s.home_title);
        if (s.label_attendance) setLabelAttendance(s.label_attendance);
        if (s.label_request) setLabelRequest(s.label_request);
        if (s.app_default_dark_mode !== undefined) setAppDefaultDarkMode(s.app_default_dark_mode === '1');

        if (s.telegram_bot_token) setTgBotToken(s.telegram_bot_token);
        if (s.telegram_chat_id) setTgChatId(s.telegram_chat_id);
        if (s.telegram_notify_attendance !== undefined) setTgNotifyAttendance(s.telegram_notify_attendance === '1');
        if (s.telegram_notify_requests !== undefined) setTgNotifyRequests(s.telegram_notify_requests === '1');
        if (s.telegram_tpl_attendance) setTgTplAttendance(s.telegram_tpl_attendance);
        if (s.telegram_tpl_request) setTgTplRequest(s.telegram_tpl_request);

        if (s.telegram_bot_token__worker) setTgBotTokenWorker(s.telegram_bot_token__worker);
        if (s.telegram_chat_id__worker) setTgChatIdWorker(s.telegram_chat_id__worker);
        if (s.telegram_notify_attendance__worker !== undefined)
          setTgNotifyAttendanceWorker(s.telegram_notify_attendance__worker === '1');
        if (s.telegram_notify_requests__worker !== undefined)
          setTgNotifyRequestsWorker(s.telegram_notify_requests__worker === '1');
        if (s.telegram_tpl_attendance__worker) setTgTplAttendanceWorker(s.telegram_tpl_attendance__worker);
        if (s.telegram_tpl_request__worker) setTgTplRequestWorker(s.telegram_tpl_request__worker);

        if (s.telegram_time_format) {
          setTgTimeFormat(s.telegram_time_format);
          setTgTimeFormatPreset(s.telegram_time_format);
        }

        if (s.attendance_reminder_enabled !== undefined) setReminderEnabled(s.attendance_reminder_enabled === '1');
        if (s.attendance_reminder_minutes) setReminderMinutes(s.attendance_reminder_minutes);
        if (s.attendance_reminder_sound) setReminderSound(s.attendance_reminder_sound);

        if (s.daily_report_telegram_enabled !== undefined) setDailyReportEnabled(s.daily_report_telegram_enabled === '1');
        if (s.daily_report_telegram_reporter_id) setDailyReportReporterId(s.daily_report_telegram_reporter_id);
        if (s.daily_report_telegram_bot_token) setDailyReportBotToken(s.daily_report_telegram_bot_token);
        if (s.daily_report_telegram_chat_id) setDailyReportChatId(s.daily_report_telegram_chat_id);
        if (s.daily_report_telegram_template) setDailyReportTemplate(s.daily_report_telegram_template);

        if (s.allowed_departments_skill) setAllowedDeptSkill(s.allowed_departments_skill);
        if (s.allowed_departments_worker) setAllowedDeptWorker(s.allowed_departments_worker);
        if (s.material_request_locations) setMaterialLocations(s.material_request_locations);

        if (s.show_column_checkbox !== undefined) setColCheckbox(s.show_column_checkbox === '1');
        if (s.show_column_employee_id !== undefined) setColEmpId(s.show_column_employee_id === '1');
        if (s.show_column_name !== undefined) setColName(s.show_column_name === '1');
        if (s.show_column_action_type !== undefined) setColAction(s.show_column_action_type === '1');
        if (s.show_column_date !== undefined) setColDate(s.show_column_date === '1');
        if (s.show_column_time !== undefined) setColTime(s.show_column_time === '1');
        if (s.show_column_status !== undefined) setColStatus(s.show_column_status === '1');
        if (s.show_column_late_reason !== undefined) setColLateReason(s.show_column_late_reason === '1');
        if (s.show_column_actions !== undefined) setColActions(s.show_column_actions === '1');

        if (s.app_theme_season) setAppThemeSeason(s.app_theme_season);
      }

      const loginRes = await adminApi.fetchLoginPageSettings();
      if (loginRes && loginRes.settings) {
        if (loginRes.settings.login_page_title) setLoginTitle(loginRes.settings.login_page_title);
        if (loginRes.settings.login_page_subtitle) setLoginSubtitle(loginRes.settings.login_page_subtitle);
        if (loginRes.settings.login_page_logo_path) setLoginLogo(loginRes.settings.login_page_logo_path);
        if (loginRes.settings.login_page_icon_class) setLoginIcon(loginRes.settings.login_page_icon_class);
      }

      const themeRes = await adminApi.fetchThemes();
      if (themeRes && themeRes.themes && Array.isArray(themeRes.themes)) {
        setThemes(themeRes.themes);
        const active = themeRes.themes.find((t: any) => t.is_active == 1);
        if (active) setActiveThemeId(active.theme_id);
      }
    } catch (err) {
      console.error('Error loading settings:', err);
    }
  };

  const loadPayrollBio = async () => {
    setLoadingBio(true);
    try {
      const res = await adminApi.fetchPayrollBiometricRecords();
      if (res && res.records && Array.isArray(res.records)) {
        setPayrollRecords(res.records);
      }
    } catch (err) {
      console.error('Error loading payroll records:', err);
    }
    setLoadingBio(false);
  };

  const handleDeleteBio = async (recordId: number) => {
    if (!window.confirm('តើអ្នកចង់លុបកំណត់ត្រា Verification នេះមែនទេ?')) return;
    try {
      await adminApi.deletePayrollBiometricRecord(recordId);
      loadPayrollBio();
    } catch (err) {
      alert('កំហុសក្នុងការលុប');
    }
  };

  const handleClearBio = async () => {
    if (!window.confirm('តើអ្នកចង់លុបកំណត់ត្រា Verification ទាំងអស់មែនទេ?')) return;
    try {
      await adminApi.clearPayrollBiometricRecords();
      loadPayrollBio();
    } catch (err) {
      alert('កំហុសក្នុងការសម្អាតកំណត់ត្រា');
    }
  };

  const loadScanHistory = async () => {
    setLoadingLogs(true);
    try {
      const res = await adminApi.fetchScanHistory();
      if (res && res.history && Array.isArray(res.history)) {
        setScanLogs(res.history);
      }
    } catch (err) {
      console.error('Error loading scan history:', err);
    }
    setLoadingLogs(false);
  };

  useEffect(() => {
    if (activeTab === 'manage_app_scan') {
      if (appScanSubTab === 'security') loadPayrollBio();
      if (appScanSubTab === 'scan-history') loadScanHistory();
    }
  }, [activeTab, appScanSubTab]);

  // Card reordering helper
  const moveRoleCard = (suffix: string, index: number, direction: 'up' | 'down') => {
    const curOrder = roleOrders[suffix] ? [...roleOrders[suffix]] : ALL_CARD_KEYS.map((c) => c.key);
    const targetIdx = direction === 'up' ? index - 1 : index + 1;
    if (targetIdx < 0 || targetIdx >= curOrder.length) return;
    const temp = curOrder[index];
    curOrder[index] = curOrder[targetIdx];
    curOrder[targetIdx] = temp;
    setRoleOrders({ ...roleOrders, [suffix]: curOrder });
  };

  const handleSaveGeneral = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedSuccess(false);
    try {
      await adminApi.saveSettings({
        panel_title: panelTitle,
        company_name: companyName,
        footer_text: footerText,
      });
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុក');
    }
    setSaving(false);
  };

  const handleSaveAppScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedSuccess(false);
    try {
      const payload: Record<string, string> = {
        app_display_name: appDisplayName,
        header_type: headerType,
        header_title: headerTitle,
        header_subtitle: headerSubtitle,
        header_logo_path: headerLogoPath,
        late_threshold_minutes: lateThreshold,
        require_face_scan: requireFaceScan ? '1' : '0',
        face_scan_enabled: requireFaceScan ? '1' : '0',
        allow_outside_scan: allowOutsideScan ? '1' : '0',
        payroll_biometric_required: payrollBiometric ? '1' : '0',
        app_latest_version: appVersion,
        app_latest_build: appBuild,
        app_apk_url: apkUrl,
        app_update_message: updateMessage,
        app_force_update: forceUpdate ? '1' : '0',
        employee_report_ids_318: branchIds318,
        employee_report_ids_ks2: branchIdsKs2,
        employee_report_ids_nr3: branchIdsNr3,
        greeting_morning: greetingMorning,
        greeting_afternoon: greetingAfternoon,
        greeting_evening: greetingEvening,
        home_title: homeTitle,
        label_attendance: labelAttendance,
        label_request: labelRequest,
        app_default_dark_mode: appDefaultDarkMode ? '1' : '0',
        telegram_bot_token: tgBotToken,
        telegram_chat_id: tgChatId,
        telegram_notify_attendance: tgNotifyAttendance ? '1' : '0',
        telegram_notify_requests: tgNotifyRequests ? '1' : '0',
        telegram_tpl_attendance: tgTplAttendance,
        telegram_tpl_request: tgTplRequest,
        telegram_bot_token__worker: tgBotTokenWorker,
        telegram_chat_id__worker: tgChatIdWorker,
        telegram_notify_attendance__worker: tgNotifyAttendanceWorker ? '1' : '0',
        telegram_notify_requests__worker: tgNotifyRequestsWorker ? '1' : '0',
        telegram_tpl_attendance__worker: tgTplAttendanceWorker,
        telegram_tpl_request__worker: tgTplRequestWorker,
        telegram_time_format: tgTimeFormat,
        attendance_reminder_enabled: reminderEnabled ? '1' : '0',
        attendance_reminder_minutes: reminderMinutes,
        attendance_reminder_sound: reminderSound,
        daily_report_telegram_enabled: dailyReportEnabled ? '1' : '0',
        daily_report_telegram_reporter_id: dailyReportReporterId,
        daily_report_telegram_bot_token: dailyReportBotToken,
        daily_report_telegram_chat_id: dailyReportChatId,
        daily_report_telegram_template: dailyReportTemplate,
        allowed_departments_skill: allowedDeptSkill,
        allowed_departments_worker: allowedDeptWorker,
        material_request_locations: materialLocations,
        show_column_checkbox: colCheckbox ? '1' : '0',
        show_column_employee_id: colEmpId ? '1' : '0',
        show_column_name: colName ? '1' : '0',
        show_column_action_type: colAction ? '1' : '0',
        show_column_date: colDate ? '1' : '0',
        show_column_time: colTime ? '1' : '0',
        show_column_status: colStatus ? '1' : '0',
        show_column_late_reason: colLateReason ? '1' : '0',
        show_column_actions: colActions ? '1' : '0',
        app_theme_season: appThemeSeason,
      };

      // Add each role's layout, card order, and card visibility checkboxes
      VISIBILITY_ROLES.forEach((r) => {
        const sfx = r.suffix;
        payload[`home_layout_type__${sfx}`] = roleLayouts[sfx] || 'grid';
        payload[`home_card_order__${sfx}`] = (roleOrders[sfx] || ALL_CARD_KEYS.map((c) => c.key)).join(',');

        const rCards = roleCards[sfx] || {};
        ALL_CARD_KEYS.forEach((c) => {
          payload[`show_${c.key}_card__${sfx}`] = rCards[c.key] ? '1' : '0';
        });
      });

      await adminApi.saveAppScanSettings(payload);
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុកការកំណត់ App Scan');
    }
    setSaving(false);
  };

  const handleSaveLoginPage = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedSuccess(false);
    try {
      await adminApi.saveLoginPageSettings({
        login_page_title: loginTitle,
        login_page_subtitle: loginSubtitle,
        login_page_logo_path: loginLogo,
        login_page_icon_class: loginIcon,
      });
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុក Login Page');
    }
    setSaving(false);
  };

  const handleSaveMenu = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedSuccess(false);
    try {
      const textMap: Record<string, string> = {};
      const orderMap: Record<string, number> = {};
      menus.forEach((m) => {
        textMap[m.key] = m.text;
        orderMap[m.key] = m.order;
      });
      await adminApi.saveMenuSettings(textMap, orderMap);
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុក Menu Settings');
    }
    setSaving(false);
  };

  const handleActivateTheme = async (themeId: string) => {
    try {
      await adminApi.setActiveTheme(themeId);
      setActiveThemeId(themeId);
      alert('បានប្តូរ Theme ជោគជ័យ!');
    } catch (err) {
      alert('កំហុសក្នុងការប្តូរ Theme');
    }
  };

  // Build the complete list of sub-tabs matching user's screenshot
  const ALL_SUB_TABS = [
    { id: 'branding', label: 'ការរចនាម៉ាកសញ្ញា (Branding)', icon: LayoutGrid },
    { id: 'app-version', label: 'កំណែកម្មវិធី & អាប់ដេត', icon: Smartphone },
    { id: 'security', label: 'Security', icon: Shield },
    ...VISIBILITY_ROLES.map((r) => ({
      id: `vis-${r.suffix}`,
      label: r.fullLabel,
      icon: Eye,
    })),
    { id: 'labels', label: 'Labels', icon: Type },
    { id: 'telegram', label: 'Telegram', icon: Send },
    { id: 'departments', label: 'Departments', icon: Building },
    { id: 'materials', label: 'សម្ភារៈ & ទីតាំង', icon: Box },
    { id: 'column-visibility', label: 'Column Visibility', icon: Columns },
    { id: 'themes', label: 'Seasonal Themes', icon: Palette },
    { id: 'scan-history', label: 'ប្រវត្តិស្កេន (Scan History)', icon: History },
  ];

  // Active role if on a visibility tab
  const activeRole = VISIBILITY_ROLES.find((r) => `vis-${r.suffix}` === appScanSubTab);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1150px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
          ការកំណត់ប្រព័ន្ធទាំងមូល (System & Admin Settings)
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          កំណត់ព័ត៌មាន Branding, ច្បាប់ស្កេនវត្តមាន App, ទំព័រ Login, ម៉ឺនុយ Menu, និង Themes
        </p>
      </div>

      {/* Navigation Main Tabs */}
      <div
        className="hrm-card"
        style={{
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
        }}
      >
        {[
          { id: 'panel_settings', label: '🏢 ការកំណត់ Panel (Panel Settings)', icon: LayoutGrid },
          { id: 'menu_settings', label: '🗂️ គ្រប់គ្រង Menu (Menu Settings)', icon: Menu },
          { id: 'login_page_settings', label: '🔐 ទំព័រ Login (Login Settings)', icon: LogIn },
          { id: 'theme_management', label: '🎨 Theme & ពណ៌ (Themes)', icon: Palette },
          { id: 'manage_app_scan', label: '📱 ច្បាប់ស្កេន App (Manage App Scan)', icon: Smartphone },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`btn btn-sm ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
              style={{ whiteSpace: 'nowrap' }}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Success Alert */}
      {savedSuccess && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: '12px',
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: '#10b981',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '13.5px',
            fontWeight: 600,
          }}
        >
          <Check size={16} />
          <span>ការកំណត់ត្រូវបានរក្សាទុកដោយជោគជ័យ!</span>
        </div>
      )}

      {/* 1. PANEL SETTINGS */}
      {activeTab === 'panel_settings' && (
        <form onSubmit={handleSaveGeneral} className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Sliders size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              ព័ត៌មានទូទៅនៃ Admin Panel (Panel Information)
            </h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '18px' }}>
            <div className="form-group">
              <label className="form-label">ឈ្មោះកម្មវិធី (Panel Display Title)</label>
              <input
                type="text"
                className="form-input"
                value={panelTitle}
                onChange={(e) => setPanelTitle(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">ឈ្មោះក្រុមហ៊ុន (Company Name)</label>
              <input
                type="text"
                className="form-input"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group" style={{ marginTop: '16px' }}>
            <label className="form-label">អត្ថបទខាងក្រោម (Footer Copyright Text)</label>
            <input
              type="text"
              className="form-input"
              value={footerText}
              onChange={(e) => setFooterText(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '24px' }}>
            <button type="submit" disabled={saving} className="btn btn-primary" style={{ padding: '10px 24px' }}>
              <Save size={16} />
              <span>{saving ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកំណត់ Panel'}</span>
            </button>
          </div>
        </form>
      )}

      {/* 2. MENU SETTINGS */}
      {activeTab === 'menu_settings' && (
        <form onSubmit={handleSaveMenu} className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Menu size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              រៀបចំម៉ឺនុយ Sidebar (Sidebar Navigation Settings)
            </h3>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            កែប្រែឈ្មោះបង្ហាញ (Label) និងលេខរៀងលំដាប់នៃម៉ឺនុយនីមួយៗក្នុងប្រព័ន្ធ
          </p>

          <div className="table-container" style={{ marginTop: '16px' }}>
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>Menu Key</th>
                  <th>ឈ្មោះបង្ហាញ (Display Label)</th>
                  <th style={{ width: '120px', textAlign: 'center' }}>លំដាប់ (Order)</th>
                </tr>
              </thead>
              <tbody>
                {menus.map((m, idx) => (
                  <tr key={m.key}>
                    <td>
                      <code style={{ fontSize: '12px' }}>{m.key}</code>
                    </td>
                    <td>
                      <input
                        type="text"
                        className="form-input"
                        value={m.text}
                        onChange={(e) => {
                          const updated = [...menus];
                          updated[idx].text = e.target.value;
                          setMenus(updated);
                        }}
                        style={{ height: '36px', fontSize: '13px' }}
                      />
                    </td>
                    <td>
                      <input
                        type="number"
                        className="form-input"
                        value={m.order}
                        onChange={(e) => {
                          const updated = [...menus];
                          updated[idx].order = parseInt(e.target.value) || 0;
                          setMenus(updated);
                        }}
                        style={{ height: '36px', textAlign: 'center' }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '24px' }}>
            <button type="submit" disabled={saving} className="btn btn-primary" style={{ padding: '10px 24px' }}>
              <Save size={16} />
              <span>{saving ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកំណត់ Menu'}</span>
            </button>
          </div>
        </form>
      )}

      {/* 3. LOGIN PAGE SETTINGS */}
      {activeTab === 'login_page_settings' && (
        <form onSubmit={handleSaveLoginPage} className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <LogIn size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              ការកំណត់ទំព័រ Login (Login Page Customization)
            </h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '18px' }}>
            <div className="form-group">
              <label className="form-label">ចំណងជើងទំព័រ Login (Title)</label>
              <input
                type="text"
                className="form-input"
                value={loginTitle}
                onChange={(e) => setLoginTitle(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Font Awesome Icon Class</label>
              <input
                type="text"
                className="form-input"
                value={loginIcon}
                onChange={(e) => setLoginIcon(e.target.value)}
                placeholder="fa-solid fa-user-shield"
              />
            </div>
          </div>

          <div className="form-group" style={{ marginTop: '16px' }}>
            <label className="form-label">សារស្វាគមន៍ (Subtitle / Welcome Text)</label>
            <input
              type="text"
              className="form-input"
              value={loginSubtitle}
              onChange={(e) => setLoginSubtitle(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '24px' }}>
            <button type="submit" disabled={saving} className="btn btn-primary" style={{ padding: '10px 24px' }}>
              <Save size={16} />
              <span>{saving ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកំណត់ Login'}</span>
            </button>
          </div>
        </form>
      )}

      {/* 4. THEME MANAGEMENT */}
      {activeTab === 'theme_management' && (
        <div className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Palette size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              ប្រព័ន្ធ Themes តាមរដូវកាល (Seasonal Theme Management)
            </h3>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '20px' }}>
            ជ្រើសរើស Palette ពណ៌ និងរូបរាងសម្រាប់ប្រើប្រាស់លើ Web Admin Panel និង Mobile App
          </p>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: '18px',
            }}
          >
            {SEASONAL_THEMES.map((t) => (
              <div
                key={t.key}
                style={{
                  border: activeThemeId === t.key ? '2px solid var(--primary)' : '1px solid var(--border)',
                  borderRadius: '16px',
                  padding: '18px',
                  background: 'var(--surface-hover)',
                  position: 'relative',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px',
                }}
              >
                {activeThemeId === t.key && (
                  <span
                    className="badge badge-good"
                    style={{ position: 'absolute', top: '14px', right: '14px' }}
                  >
                    កំពុងដំណើរការ (Active)
                  </span>
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ width: '22px', height: '22px', borderRadius: '50%', background: t.color }} />
                  <div style={{ width: '22px', height: '22px', borderRadius: '50%', background: t.bg }} />
                </div>

                <div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {t.name}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {t.desc}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleActivateTheme(t.key)}
                  className={`btn btn-sm ${activeThemeId === t.key ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ width: '100%', justifyContent: 'center' }}
                >
                  <Check size={14} />
                  <span>{activeThemeId === t.key ? 'Theme បច្ចុប្បន្ន' : 'ជ្រើសរើស Theme នេះ'}</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. MANAGE APP SCAN - FULL 27 SUB-TABS (EXACT MATCHING ADMIN_ATTENDANCE.PHP) */}
      {activeTab === 'manage_app_scan' && (
        <form onSubmit={handleSaveAppScan} className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Smartphone size={22} color="var(--primary)" />
            <div>
              <h3 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                ការកំណត់កម្មវិធី Mobile App (Manage App Scan Settings)
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                គ្រប់គ្រង branding, visibility តាម Role នីមួយៗ, version update និង mobile options
              </p>
            </div>
          </div>

          {/* Sub-Tabs Shell (Exact match with user's screenshot) */}
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '8px',
              padding: '12px',
              background: 'var(--surface-hover)',
              borderRadius: '16px',
              marginBottom: '24px',
              border: '1px solid var(--border)',
            }}
          >
            {ALL_SUB_TABS.map((sub) => {
              const SubIcon = sub.icon;
              const isActive = appScanSubTab === sub.id;
              return (
                <button
                  type="button"
                  key={sub.id}
                  onClick={() => setAppScanSubTab(sub.id)}
                  className={`btn btn-sm ${isActive ? 'btn-primary' : 'btn-secondary'}`}
                  style={{
                    fontSize: '12px',
                    padding: '8px 14px',
                    borderRadius: '12px',
                    fontWeight: isActive ? 800 : 500,
                    boxShadow: isActive ? '0 4px 12px rgba(37, 99, 235, 0.25)' : 'none',
                  }}
                >
                  <SubIcon size={13} />
                  <span>{sub.label}</span>
                </button>
              );
            })}
          </div>

          {/* TAB 1: BRANDING */}
          {appScanSubTab === 'branding' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ការរចនាម៉ាកសញ្ញា (App Branding)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  ការផ្លាស់ប្តូរនៅទីនេះនឹងប៉ះពាល់ដល់រូបរាងកម្មវិធីខាងក្នុង (Login, App Bar, Headers)
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">ឈ្មោះកម្មវិធី (App Display Name)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={appDisplayName}
                    onChange={(e) => setAppDisplayName(e.target.value)}
                    placeholder="VVC ATTENDANCE"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ប្រភេទ Header ក្នុង App</label>
                  <select
                    className="form-input"
                    value={headerType}
                    onChange={(e) => setHeaderType(e.target.value)}
                  >
                    <option value="title">បង្ហាញតែឈ្មោះ (Title)</option>
                    <option value="logo">បង្ហាញតែ Logo</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">ឈ្មោះ Header (Header Title)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={headerTitle}
                    onChange={(e) => setHeaderTitle(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ចំណងជើងរង (Header Subtitle)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={headerSubtitle}
                    onChange={(e) => setHeaderSubtitle(e.target.value)}
                    placeholder="Optional subtitle"
                  />
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: VERSION & UPDATE */}
          {appScanSubTab === 'app-version' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ការគ្រប់គ្រងកំណែកម្មវិធី (App Version Control & Update)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  កំណត់កំណែកម្មវិធីចុងក្រោយ និងសារជូនដំណឹងពេលមានការអាប់ដេត
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">លេខជំនាន់ (Latest Version)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={appVersion}
                    onChange={(e) => setAppVersion(e.target.value)}
                    placeholder="1.0.5"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">លេខ Build (Build Number)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={appBuild}
                    onChange={(e) => setAppBuild(e.target.value)}
                    placeholder="5"
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">តំណភ្ជាប់ទាញយក APK (APK Download URL)</label>
                <input
                  type="url"
                  className="form-input"
                  value={apkUrl}
                  onChange={(e) => setApkUrl(e.target.value)}
                  placeholder="https://app.vvc.asia/downloads/app.apk"
                />
              </div>

              <div className="form-group">
                <label className="form-label">សារជូនដំណឹងការអាប់ដេត (Update Message / Release Notes)</label>
                <textarea
                  className="form-textarea"
                  rows={3}
                  value={updateMessage}
                  onChange={(e) => setUpdateMessage(e.target.value)}
                />
              </div>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={forceUpdate}
                  onChange={(e) => setForceUpdate(e.target.checked)}
                  style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                />
                <span style={{ fontSize: '13.5px', color: 'var(--text-primary)', fontWeight: 600 }}>
                  តម្រូវឱ្យអាប់ដេតជាកំហិត (Force Update Mode - មិនអាចប្រើ App ចាស់បានទេ)
                </span>
              </label>
            </div>
          )}

          {/* TAB 3: SECURITY & BIOMETRICS */}
          {appScanSubTab === 'security' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ការកំណត់សុវត្ថិភាព (Security & Biometrics)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  គ្រប់គ្រងការការពារទិន្នន័យសំខាន់ៗក្នុង mobile app
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={payrollBiometric}
                    onChange={(e) => setPayrollBiometric(e.target.checked)}
                    style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                  />
                  <div>
                    <span style={{ fontSize: '13.5px', color: 'var(--text-primary)', fontWeight: 600 }}>
                      តម្រូវឱ្យស្កេន Face ID / ស្នាមម្រាមដៃ មុនមើលប្រាក់ខែ (Payroll Biometric Required)
                    </span>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0' }}>
                      ទូរស័ព្ទនឹងផ្ទៀងផ្ទាត់ Biometric ដោយផ្ទាល់ មុនបង្ហាញព័ត៌មានប្រាក់បៀវត្ស
                    </p>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={requireFaceScan}
                    onChange={(e) => setRequireFaceScan(e.target.checked)}
                    style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                  />
                  <div>
                    <span style={{ fontSize: '13.5px', color: 'var(--text-primary)', fontWeight: 600 }}>
                      បើកដំណើរការស្កេនផ្ទៃមុខសម្រាប់វត្តមាន (Face Recognition Check-in)
                    </span>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={allowOutsideScan}
                    onChange={(e) => setAllowOutsideScan(e.target.checked)}
                    style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                  />
                  <div>
                    <span style={{ fontSize: '13.5px', color: 'var(--text-primary)', fontWeight: 600 }}>
                      អនុញ្ញាតឱ្យស្កេនក្រៅទីតាំង (Outside Check-In Mode)
                    </span>
                  </div>
                </label>

                <div className="form-group" style={{ maxWidth: '240px', marginTop: '8px' }}>
                  <label className="form-label">កម្រិតកំណត់មកយឺត (Late Threshold Minutes)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={lateThreshold}
                    onChange={(e) => setLateThreshold(e.target.value)}
                  />
                </div>
              </div>

              {/* Payroll Biometric Records Table */}
              <div
                style={{
                  marginTop: '16px',
                  borderRadius: '14px',
                  border: '1px solid var(--border)',
                  overflow: 'hidden',
                  background: 'var(--surface)',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '14px 18px',
                    background: 'var(--surface-hover)',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div>
                    <h5 style={{ margin: 0, fontWeight: 700, color: 'var(--text-primary)' }}>
                      អ្នកដែលបានផ្ទៀងផ្ទាត់ Payroll Biometric ({payrollRecords.length})
                    </h5>
                    <p style={{ margin: '2px 0 0', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                      កំណត់ត្រា verification record ប៉ុណ្ណោះ មិនមែនទិន្នន័យមុខទេ
                    </p>
                  </div>
                  {payrollRecords.length > 0 && (
                    <button
                      type="button"
                      onClick={handleClearBio}
                      className="btn btn-secondary btn-sm"
                      style={{ color: '#ef4444', borderColor: '#ef4444' }}
                    >
                      <Trash2 size={13} />
                      <span>លុបទាំងអស់ (Clear All)</span>
                    </button>
                  )}
                </div>

                <div className="table-container" style={{ margin: 0, maxHeight: '280px', overflowY: 'auto' }}>
                  <table className="hrm-table">
                    <thead>
                      <tr>
                        <th>បុគ្គលិក (Employee)</th>
                        <th>Platform</th>
                        <th>ចំនួនដង</th>
                        <th>ផ្ទៀងផ្ទាត់ចុងក្រោយ</th>
                        <th>IP Address</th>
                        <th style={{ width: '80px' }}>សកម្មភាព</th>
                      </tr>
                    </thead>
                    <tbody>
                      {payrollRecords.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                            {loadingBio ? 'កំពុងទាញយក...' : 'មិនទាន់មានអ្នកផ្ទៀងផ្ទាត់ Payroll Biometric ទេ'}
                          </td>
                        </tr>
                      ) : (
                        payrollRecords.map((r: any) => (
                          <tr key={r.id}>
                            <td>
                              <strong>{r.employee_name || r.employee_id}</strong>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                ID: {r.employee_id} {r.department ? `| ${r.department}` : ''}
                              </div>
                            </td>
                            <td>{r.last_platform || '-'}</td>
                            <td>{r.verification_count || 1}</td>
                            <td style={{ fontSize: '12px' }}>{r.last_verified_at_formatted || r.last_verified_at}</td>
                            <td style={{ fontSize: '12px', fontFamily: 'monospace' }}>{r.last_ip_address || '-'}</td>
                            <td>
                              <button
                                type="button"
                                onClick={() => handleDeleteBio(r.id)}
                                className="btn btn-secondary btn-sm"
                                style={{ padding: '4px 8px', color: '#ef4444' }}
                              >
                                <Trash2 size={12} />
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4..20: VISIBILITY ROLE TABS (FOR EVERY ROLE) */}
          {activeRole && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'var(--surface-hover)',
                  padding: '16px 20px',
                  borderRadius: '14px',
                  border: '1px solid var(--border)',
                }}
              >
                <div>
                  <h4 style={{ margin: 0, color: 'var(--primary)', fontWeight: 800, fontSize: '15px' }}>
                    <Eye size={16} style={{ display: 'inline', marginRight: '8px' }} />
                    ការកំណត់បង្ហាញសម្រាប់ {activeRole.label}
                  </h4>
                  <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                    កំណត់មុខងារដែល {activeRole.label} អាចមើលឃើញ និងអូសតម្រៀប
                  </p>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    ទម្រង់បង្ហាញ Card (Layout):
                  </span>
                  <select
                    className="form-input"
                    value={roleLayouts[activeRole.suffix] || 'grid'}
                    onChange={(e) =>
                      setRoleLayouts({ ...roleLayouts, [activeRole.suffix]: e.target.value })
                    }
                    style={{ width: '190px', height: '36px', fontSize: '12.5px' }}
                  >
                    <option value="grid">Grid Layout (Standard)</option>
                    <option value="list">List Layout (Card List - Unified)</option>
                  </select>
                </div>
              </div>

              {/* Individual Branch ID Box for Staff */}
              {activeRole.showBranch && (
                <div
                  style={{
                    padding: '16px',
                    borderRadius: '12px',
                    background: '#f0f9ff',
                    border: '1px solid #bae6fd',
                  }}
                >
                  <h5 style={{ margin: '0 0 10px', fontSize: '13px', fontWeight: 700, color: '#0369a1' }}>
                    <Shield size={14} style={{ display: 'inline', marginRight: '6px' }} />
                    សិទ្ធិកម្រិតបុគ្គល (Individual ID Report)
                  </h5>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                    <div className="form-group">
                      <label style={{ fontSize: '11.5px', fontWeight: 600, color: '#0c4a6e' }}>
                        IDs អាចមើល សាខា 318 (ចែកដោយសញ្ញាក្បៀស ,)
                      </label>
                      <input
                        type="text"
                        className="form-input"
                        value={branchIds318}
                        onChange={(e) => setBranchIds318(e.target.value)}
                        placeholder="ឧ. 0123,0124"
                      />
                    </div>
                    <div className="form-group">
                      <label style={{ fontSize: '11.5px', fontWeight: 600, color: '#0c4a6e' }}>
                        IDs អាចមើល សាខា KS2 (ចែកដោយសញ្ញាក្បៀស ,)
                      </label>
                      <input
                        type="text"
                        className="form-input"
                        value={branchIdsKs2}
                        onChange={(e) => setBranchIdsKs2(e.target.value)}
                        placeholder="ឧ. 0123,0124"
                      />
                    </div>
                    <div className="form-group">
                      <label style={{ fontSize: '11.5px', fontWeight: 600, color: '#0c4a6e' }}>
                        IDs អាចមើល សាខា NR3 (ចែកដោយសញ្ញាក្បៀស ,)
                      </label>
                      <input
                        type="text"
                        className="form-input"
                        value={branchIdsNr3}
                        onChange={(e) => setBranchIdsNr3(e.target.value)}
                        placeholder="ឧ. 0123,0124"
                      />
                    </div>
                  </div>
                  <small style={{ display: 'block', marginTop: '8px', color: '#075985', fontSize: '11px', fontStyle: 'italic' }}>
                    * បញ្ជាក់៖ បញ្ចូល ID បុគ្គលិកនៅទីនេះ ដើម្បីឱ្យគាត់ឃើញប៊ូតុង "របាយការណ៍វត្តមាន" និងកំណត់មើលតាមសាខាដែលបានដាក់។
                  </small>
                </div>
              )}

              {/* 25 Cards List for this Role */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                {(roleOrders[activeRole.suffix] || ALL_CARD_KEYS.map((c) => c.key)).map((key, idx) => {
                  const def = ALL_CARD_KEYS.find((c) => c.key === key) || { key, label: key };
                  const rCards = roleCards[activeRole.suffix] || {};
                  const isVisible = rCards[key] ?? !activeRole.isWorker;

                  return (
                    <div
                      key={key}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 16px',
                        borderRadius: '10px',
                        background: isVisible ? 'var(--surface-hover)' : 'rgba(100, 116, 139, 0.08)',
                        border: isVisible ? '1px solid var(--border)' : '1px dashed var(--border)',
                        opacity: isVisible ? 1 : 0.65,
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <button
                            type="button"
                            disabled={idx === 0}
                            onClick={() => moveRoleCard(activeRole.suffix, idx, 'up')}
                            className="btn btn-secondary btn-sm"
                            style={{ padding: '2px 6px', height: '20px', minWidth: '24px' }}
                          >
                            <ChevronUp size={12} />
                          </button>
                          <button
                            type="button"
                            disabled={
                              idx ===
                              (roleOrders[activeRole.suffix] || ALL_CARD_KEYS.map((c) => c.key)).length - 1
                            }
                            onClick={() => moveRoleCard(activeRole.suffix, idx, 'down')}
                            className="btn btn-secondary btn-sm"
                            style={{ padding: '2px 6px', height: '20px', minWidth: '24px' }}
                          >
                            <ChevronDown size={12} />
                          </button>
                        </div>

                        <span
                          style={{
                            width: '24px',
                            height: '24px',
                            borderRadius: '50%',
                            background: 'var(--primary)',
                            color: 'white',
                            fontSize: '11px',
                            fontWeight: 700,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          {idx + 1}
                        </span>

                        <div>
                          <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {def.label}
                          </div>
                        </div>
                      </div>

                      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={isVisible}
                          onChange={(e) => {
                            const updated = { ...rCards, [key]: e.target.checked };
                            setRoleCards({ ...roleCards, [activeRole.suffix]: updated });
                          }}
                          style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                        />
                      </label>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB: LABELS & LANGUAGES */}
          {appScanSubTab === 'labels' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ការកំណត់អក្សរ និងភាសា (App Labels)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  កំណត់ពាក្យស្វាគមន៍ និងអក្សរប៊ូតុងសំខាន់ៗលើ Mobile App
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label">Greeting (អរុណសួស្តី ពេលព្រឹក)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={greetingMorning}
                    onChange={(e) => setGreetingMorning(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Greeting (ទិវាសួស្តី ពេលថ្ងៃ)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={greetingAfternoon}
                    onChange={(e) => setGreetingAfternoon(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Greeting (សាយណ្ហសួស្តី ពេលល្ងាច)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={greetingEvening}
                    onChange={(e) => setGreetingEvening(e.target.value)}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label">ចំណងជើងទំព័រដើម (Home Title)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={homeTitle}
                    onChange={(e) => setHomeTitle(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ប៊ូតុងស្កេនវត្តមាន (Attendance Label)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={labelAttendance}
                    onChange={(e) => setLabelAttendance(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ប៊ូតុងសំណើ (Requests Label)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={labelRequest}
                    onChange={(e) => setLabelRequest(e.target.value)}
                  />
                </div>
              </div>

              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', marginTop: '6px' }}>
                <input
                  type="checkbox"
                  checked={appDefaultDarkMode}
                  onChange={(e) => setAppDefaultDarkMode(e.target.checked)}
                  style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                />
                <span style={{ fontSize: '13.5px', color: 'var(--text-primary)', fontWeight: 600 }}>
                  ប្រើ Dark Mode ជា Standard លើ Mobile App (Standard Dark Mode)
                </span>
              </label>
            </div>
          )}

          {/* TAB: TELEGRAM CONFIGURATION */}
          {appScanSubTab === 'telegram' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ការកំណត់ Telegram (Telegram Configuration)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  កំណត់ Bot Token, Chat ID, Notifications, Reminders និង Daily Report
                </p>
              </div>

              {/* General Bot Card */}
              <div
                style={{
                  padding: '18px',
                  borderRadius: '14px',
                  border: '1px solid var(--border)',
                  background: 'var(--surface-hover)',
                }}
              >
                <h5 style={{ margin: '0 0 14px', fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  🤖 ការកំណត់ Bot រួម (General Bot Settings)
                </h5>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div className="form-group">
                    <label className="form-label">Bot Token (General)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={tgBotToken}
                      onChange={(e) => setTgBotToken(e.target.value)}
                      placeholder="123456789:ABCDEF..."
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Chat ID / Group ID (General)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={tgChatId}
                      onChange={(e) => setTgChatId(e.target.value)}
                      placeholder="-100XXXXXXXXXX"
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '20px', margin: '12px 0' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={tgNotifyAttendance}
                      onChange={(e) => setTgNotifyAttendance(e.target.checked)}
                      style={{ width: '17px', height: '17px', accentColor: 'var(--primary)' }}
                    />
                    <span style={{ fontSize: '13px', fontWeight: 600 }}>ផ្ញើសារពេល Check-In/Out</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={tgNotifyRequests}
                      onChange={(e) => setTgNotifyRequests(e.target.checked)}
                      style={{ width: '17px', height: '17px', accentColor: 'var(--primary)' }}
                    />
                    <span style={{ fontSize: '13px', fontWeight: 600 }}>ផ្ញើសារពេលមាន Request ថ្មី</span>
                  </label>
                </div>

                <div className="form-group" style={{ marginTop: '10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <label className="form-label" style={{ margin: 0 }}>
                      គំរូសារវត្តមាន (General Attendance Template)
                    </label>
                    <button
                      type="button"
                      onClick={() => setShowPreviewGenAtt(!showPreviewGenAtt)}
                      className="btn btn-secondary btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px' }}
                    >
                      {showPreviewGenAtt ? 'បិទ Preview' : 'មើល Preview'}
                    </button>
                  </div>
                  <textarea
                    className="form-textarea"
                    rows={4}
                    value={tgTplAttendance}
                    onChange={(e) => setTgTplAttendance(e.target.value)}
                    style={{ fontFamily: 'monospace', fontSize: '12px' }}
                  />
                  {showPreviewGenAtt && (
                    <div
                      style={{
                        marginTop: '8px',
                        padding: '12px',
                        borderRadius: '8px',
                        background: 'rgba(59, 130, 246, 0.1)',
                        border: '1px dashed #3b82f6',
                        fontSize: '12px',
                        whiteSpace: 'pre-wrap',
                      }}
                    >
                      {tgTplAttendance
                        .replace('{{name}}', 'Sok San')
                        .replace('{{action}}', 'Check-In')
                        .replace('{{status}}', 'Good')
                        .replace('{{late_reason}}', 'None')
                        .replace('{{employee_id}}', 'VVC-001')
                        .replace('{{field_department}}', 'IT')
                        .replace('{{field_position}}', 'Developer')
                        .replace('{{time}}', '2026-08-24 08:00:00')
                        .replace('{{location_name}}', 'Main Office (318)')
                        .replace('{{distance_m}}', '12')
                        .replace('{{map_url}}', 'https://maps.google.com/?q=11.55,104.91')}
                    </div>
                  )}
                </div>
              </div>

              {/* Worker Overrides Card */}
              <div
                style={{
                  padding: '18px',
                  borderRadius: '14px',
                  border: '1px solid #fef3c7',
                  background: '#fffdf5',
                }}
              >
                <h5 style={{ margin: '0 0 14px', fontSize: '13.5px', fontWeight: 700, color: '#b45309' }}>
                  👷 ការកំណត់សម្រាប់ កម្មករ (Worker Overrides)
                </h5>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div className="form-group">
                    <label className="form-label">Bot Token (Worker Override)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={tgBotTokenWorker}
                      onChange={(e) => setTgBotTokenWorker(e.target.value)}
                      placeholder="Fallback: ប្រើ General Bot Token"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Chat ID (Worker Override)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={tgChatIdWorker}
                      onChange={(e) => setTgChatIdWorker(e.target.value)}
                      placeholder="Fallback: ប្រើ General Chat ID"
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '20px', margin: '12px 0' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={tgNotifyAttendanceWorker}
                      onChange={(e) => setTgNotifyAttendanceWorker(e.target.checked)}
                      style={{ width: '17px', height: '17px', accentColor: '#f59e0b' }}
                    />
                    <span style={{ fontSize: '13px', fontWeight: 600 }}>ផ្ញើសារវត្តមាន (Worker)</span>
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={tgNotifyRequestsWorker}
                      onChange={(e) => setTgNotifyRequestsWorker(e.target.checked)}
                      style={{ width: '17px', height: '17px', accentColor: '#f59e0b' }}
                    />
                    <span style={{ fontSize: '13px', fontWeight: 600 }}>ផ្ញើសារសំណើ (Worker)</span>
                  </label>
                </div>
              </div>

              {/* Time Format Card */}
              <div
                style={{
                  padding: '18px',
                  borderRadius: '14px',
                  border: '1px solid var(--border)',
                  background: 'var(--surface)',
                }}
              >
                <h5 style={{ margin: '0 0 14px', fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  🕒 ទម្រង់ពេលវេលា (Time Formatting)
                </h5>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div className="form-group">
                    <label className="form-label">ជ្រើសរើស Presets</label>
                    <select
                      className="form-input"
                      value={tgTimeFormatPreset}
                      onChange={(e) => {
                        setTgTimeFormatPreset(e.target.value);
                        setTgTimeFormat(e.target.value);
                      }}
                    >
                      <option value="Y-m-d H:i:s">2026-08-24 08:00:00 (Standard SQL)</option>
                      <option value="d/m/Y H:i:s">24/08/2026 08:00:00 (DD/MM/YYYY)</option>
                      <option value="d-m-Y h:i A">24-08-2026 08:00 AM (12 Hours)</option>
                      <option value="M j, Y g:i A">Aug 24, 2026 8:00 AM (English Short)</option>
                      <option value="d F Y H:i">24 August 2026 08:00 (Full Month)</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Custom Format (PHP Date)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={tgTimeFormat}
                      onChange={(e) => setTgTimeFormat(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              {/* Attendance Reminders */}
              <div
                style={{
                  padding: '18px',
                  borderRadius: '14px',
                  border: '1px solid var(--border)',
                  background: 'var(--surface)',
                }}
              >
                <h5 style={{ margin: '0 0 14px', fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  🔔 ការរំលឹកស្កេនវត្តមាន (Attendance Reminders)
                </h5>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', marginBottom: '12px' }}>
                  <input
                    type="checkbox"
                    checked={reminderEnabled}
                    onChange={(e) => setReminderEnabled(e.target.checked)}
                    style={{ width: '17px', height: '17px', accentColor: 'var(--primary)' }}
                  />
                  <span style={{ fontSize: '13.5px', fontWeight: 600 }}>បើកដំណើរការរំលឹកស្វ័យប្រវត្តិ (Auto Reminders)</span>
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div className="form-group">
                    <label className="form-label">រំលឹកមុន (Minutes Before Shift)</label>
                    <input
                      type="number"
                      className="form-input"
                      value={reminderMinutes}
                      onChange={(e) => setReminderMinutes(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">ប្រភេទសម្លេង (Sound Type)</label>
                    <select
                      className="form-input"
                      value={reminderSound}
                      onChange={(e) => setReminderSound(e.target.value)}
                    >
                      <option value="default">Default Notification</option>
                      <option value="call">Call Ringtone (Urgent)</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: DEPARTMENTS WHITELIST */}
          {appScanSubTab === 'departments' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ការកំណត់ Whitelist នាយកដ្ឋាន/មន្ទីរ (Department Whitelist)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  កំណត់ឈ្មោះនាយកដ្ឋានដែលអនុញ្ញាតឱ្យប្រើ App (បំបែកដោយសញ្ញាក្បៀស ,)
                </p>
              </div>

              <div className="form-group">
                <label className="form-label">មន្ទីរសម្រាប់ បុគ្គលិក (Staff/Employee)</label>
                <input
                  type="text"
                  className="form-input"
                  value={allowedDeptSkill}
                  onChange={(e) => setAllowedDeptSkill(e.target.value)}
                  placeholder="Finance, HR, IT, Management"
                />
              </div>

              <div className="form-group">
                <label className="form-label">មន្ទីរសម្រាប់ កម្មករ (Worker)</label>
                <input
                  type="text"
                  className="form-input"
                  value={allowedDeptWorker}
                  onChange={(e) => setAllowedDeptWorker(e.target.value)}
                  placeholder="Factory A, Factory B, Warehouse"
                />
              </div>
            </div>
          )}

          {/* TAB: MATERIALS & LOCATIONS */}
          {appScanSubTab === 'materials' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  ទីតាំងស្នើសុំសម្ភារៈ (Material Request Locations)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  កំណត់បញ្ជីទីតាំងសម្រាប់បុគ្គលិកជ្រើសរើសពេលស្នើសុំសម្ភារៈ (បំបែកដោយសញ្ញាក្បៀស ,)
                </p>
              </div>

              <div className="form-group">
                <label className="form-label">បញ្ជីទីតាំង (Locations List)</label>
                <textarea
                  className="form-textarea"
                  rows={4}
                  value={materialLocations}
                  onChange={(e) => setMaterialLocations(e.target.value)}
                />
              </div>
            </div>
          )}

          {/* TAB: COLUMN VISIBILITY */}
          {appScanSubTab === 'column-visibility' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  កំណត់ការបង្ហាញជួរឈរ (Column Visibility Settings)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  ជ្រើសរើសជួរឈរ (Columns) ដែលត្រូវបង្ហាញក្នុងតារាងរបាយការណ៍វត្តមាន
                </p>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
                  gap: '12px',
                }}
              >
                {[
                  { label: 'Checkbox (ជ្រើសរើស)', val: colCheckbox, set: setColCheckbox },
                  { label: 'Employee ID (អត្តលេខ)', val: colEmpId, set: setColEmpId },
                  { label: 'Name (ឈ្មោះ)', val: colName, set: setColName },
                  { label: 'Action Type (សកម្មភាព)', val: colAction, set: setColAction },
                  { label: 'Date (កាលបរិច្ឆេទ)', val: colDate, set: setColDate },
                  { label: 'Time (ពេលវេលា)', val: colTime, set: setColTime },
                  { label: 'Status (ស្ថានភាព)', val: colStatus, set: setColStatus },
                  { label: 'Late Reason (មូលហេតុ)', val: colLateReason, set: setColLateReason },
                  { label: 'Actions (សកម្មភាព)', val: colActions, set: setColActions },
                ].map((col, idx) => (
                  <label
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '12px 14px',
                      background: 'var(--surface-hover)',
                      borderRadius: '10px',
                      border: '1px solid var(--border)',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={col.val}
                      onChange={(e) => col.set(e.target.checked)}
                      style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
                    />
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {col.label}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* TAB: SEASONAL THEMES */}
          {appScanSubTab === 'themes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  គ្រប់គ្រង Theme កម្មវិធីតាមរដូវកាល (Seasonal Themes)
                </h4>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                  ជ្រើសរើស Theme សម្រាប់ Mobile App តាមរដូវកាលបុណ្យជាតិ
                </p>
              </div>

              <div className="form-group" style={{ maxWidth: '360px' }}>
                <label className="form-label">ជ្រើសរើស Theme បច្ចុប្បន្ន</label>
                <select
                  className="form-input"
                  value={appThemeSeason}
                  onChange={(e) => setAppThemeSeason(e.target.value)}
                >
                  {SEASONAL_THEMES.map((t) => (
                    <option key={t.key} value={t.key}>
                      {t.desc}
                    </option>
                  ))}
                </select>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                  gap: '16px',
                }}
              >
                {SEASONAL_THEMES.map((t) => {
                  const isCur = appThemeSeason === t.key;
                  return (
                    <div
                      key={t.key}
                      onClick={() => setAppThemeSeason(t.key)}
                      style={{
                        border: isCur ? '2px solid var(--primary)' : '1px solid var(--border)',
                        borderRadius: '12px',
                        padding: '12px',
                        textAlign: 'center',
                        background: t.bg,
                        cursor: 'pointer',
                        position: 'relative',
                        boxShadow: isCur ? '0 4px 12px rgba(99, 102, 241, 0.2)' : 'none',
                        transition: 'transform 0.15s ease',
                      }}
                    >
                      {isCur && (
                        <div
                          style={{
                            position: 'absolute',
                            top: '-8px',
                            right: '-8px',
                            background: 'var(--primary)',
                            color: 'white',
                            width: '22px',
                            height: '22px',
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '11px',
                          }}
                        >
                          <Check size={13} />
                        </div>
                      )}
                      <div
                        style={{
                          height: '70px',
                          background: t.color,
                          borderRadius: '8px',
                          marginBottom: '10px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: t.text,
                          fontWeight: 800,
                          fontSize: '14px',
                        }}
                      >
                        {t.name}
                      </div>
                      <div style={{ fontSize: '12px', fontWeight: isCur ? 700 : 500, color: 'var(--text-primary)' }}>
                        {t.desc}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB: SCAN HISTORY LOGS */}
          {appScanSubTab === 'scan-history' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h4 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                    ប្រវត្តិស្កេនវត្តមានចុងក្រោយ (Scan History Logs)
                  </h4>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
                    បង្ហាញកំណត់ត្រាស្កេនវត្តមានចុងក្រោយបំផុតចំនួន ១០០ ពី Mobile App
                  </p>
                </div>
                <button
                  type="button"
                  onClick={loadScanHistory}
                  className="btn btn-secondary btn-sm"
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  <RefreshCw size={13} className={loadingLogs ? 'animate-spin' : ''} />
                  <span>{loadingLogs ? 'កំពុងទាញយក...' : 'ផ្ទុកទិន្នន័យឡើងវិញ'}</span>
                </button>
              </div>

              <div className="table-container" style={{ maxHeight: '480px', overflowY: 'auto' }}>
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th>បុគ្គលិក (Employee)</th>
                      <th>សកម្មភាព</th>
                      <th>ពេលវេលា</th>
                      <th>ស្ថានភាព</th>
                      <th>ទីតាំង</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanLogs.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '28px', color: 'var(--text-muted)' }}>
                          {loadingLogs ? 'កំពុងទាញយកទិន្នន័យ...' : 'មិនទាន់មានទិន្នន័យស្កេននៅឡើយទេ'}
                        </td>
                      </tr>
                    ) : (
                      scanLogs.map((l: any, idx: number) => (
                        <tr key={idx}>
                          <td>
                            <strong>{l.user_name || l.employee_id}</strong>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ID: {l.employee_id}</div>
                          </td>
                          <td>
                            <span className={`badge ${l.action_type === 'Check-In' ? 'badge-good' : 'badge-pending'}`}>
                              {l.action_type}
                            </span>
                          </td>
                          <td style={{ fontSize: '12.5px' }}>{l.log_datetime}</td>
                          <td>
                            <span
                              className={`badge ${
                                l.status === 'Good' || l.status === 'Normal' ? 'badge-good' : 'badge-late'
                              }`}
                            >
                              {l.status}
                            </span>
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{l.location_name || '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Submit Button */}
          {appScanSubTab !== 'scan-history' && (
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '28px' }}>
              <button type="submit" disabled={saving} className="btn btn-primary" style={{ padding: '10px 24px' }}>
                <Save size={16} />
                <span>{saving ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកំណត់ App Scan'}</span>
              </button>
            </div>
          )}
        </form>
      )}
    </div>
  );
};
