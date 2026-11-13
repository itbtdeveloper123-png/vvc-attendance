# 🎨 VVC Attendance — Mobile UI Design System & Coding Guidelines
> **ស្តង់ដាររួមសម្រាប់ការរចនា Interface និងសរសេរកូដ Mobile App (Flutter)**  
> គោលបំណង៖ កម្ចាត់ UI Fragmentation, ប៊ូតុងត្រប៉ែត (oval stretch), និងខុសរង្វង់ ធានាឱ្យកម្មវិធីទាំងមូលមានភាពស៊ីសង្វាក់គ្នា ១០០% ដូច Telegram & Apple iOS។

---

## ១. គោលការណ៍ស្នូល (Design Tokens)

ឯកសារកូដស្នូល៖ `lib/widgets/vvc_design_system.dart`

```dart
import 'package:flutter_app/widgets/vvc_design_system.dart';
```

### 1.1 កាំរង្វង់ (Corner Radii)
| Token | តម្លៃ | គោលបំណង និងទីតាំងប្រើប្រាស់ |
| :--- | :--- | :--- |
| `AppTokens.radiusPill` | `999.0` | **Capsule 100%**: ប្រើសម្រាប់ប៊ូតុង (Buttons), Search Bar, Filter Tabs, Badges |
| `AppTokens.radiusCard` | `22.0` | **Bento Squircle**: ប្រើសម្រាប់ Cards, BottomSheets, Modal Dialogs |
| `AppTokens.radiusInner` | `14.0` | **Nested Item**: ប្រើសម្រាប់ Sub-sections, Inner List Tiles |
| `AppTokens.radiusSmall` | `10.0` | **Mini Tag**: ប្រើសម្រាប់ Tag តូចៗ, Counter badges |

> [!CAUTION]
> **ហាមដាច់ខាត**៖ មិនត្រូវសរសេរ `BorderRadius.circular(10/12/14/16/20)` ដោយដៃតាមចិត្តលើប៊ូតុងឡើយ! ត្រូវតែជា `AppTokens.radiusPill` (Capsule 100%)។

---

### 1.2 កម្ពស់ស្តង់ដារ (Standard Heights)
- `AppTokens.heightHeroBtn = 52.0`: Check-In / Check-Out, Submit, Primary Hero CTAs
- `AppTokens.heightStandardBtn = 44.0`: Standard Dialog Action, Form Submit
- `AppTokens.heightCompactBtn = 38.0`: Scan Login, Copy Code, Secondary Action Pills
- `AppTokens.heightMiniBtn = 30.0`: Table Action, Small Badge Pill
- `AppTokens.heightSearch = 42.0`: Universal Search Bar
- `AppTokens.heightFilterChip = 36.0`: Telegram Category Filter Tabs
- `AppTokens.sizePodLarge = 44.0`: Large Header Circular Action Pod
- `AppTokens.sizePodStandard = 38.0`: Standard Header Circular Action Pod

---

## ២. បណ្ណាល័យ Atomic Components

### 2.1 ប៊ូតុង Capsule ស្វ័យប្រវត្តិ (`VvcPillButton`)
មានភ្ជាប់មកជាមួយនូវ **Telegram Spring Bounce**, Haptic Feedback, និង Full Capsule Shape៖

```dart
// ១. ប៊ូតុងមាស VVC Gold CTA (Check-in, Confirm, Primary)
VvcPillButton(
  text: 'ស្កេនចូល (Check-In)',
  icon: CupertinoIcons.qrcode_viewfinder,
  variant: VvcPillVariant.gold,
  size: VvcButtonSize.hero, // កម្ពស់ 52px
  onTap: () => _handleCheckIn(),
)

// ២. ប៊ូតុងពណ៌ខៀវ (Login, Scan, Secondary Primary)
VvcPillButton(
  text: 'ស្កេន Login',
  icon: Icons.qr_code_scanner_rounded,
  variant: VvcPillVariant.blue,
  size: VvcButtonSize.compact, // កម្ពស់ 38px
  onTap: () => _handleScanLogin(),
)

// ៣. ប៊ូតុងកញ្ចក់ Frosted Glass (Outside attendance, Filter, Cancel)
VvcPillButton(
  text: 'ក្រៅទីតាំង',
  icon: CupertinoIcons.location_solid,
  variant: VvcPillVariant.glass,
  size: VvcButtonSize.hero,
  onTap: () => _handleOutside(),
)

// ៤. ប៊ូតុងគ្រោះថ្នាក់ Danger Red (Check-out, Delete)
VvcPillButton(
  text: 'ស្កេនចេញ (Check-Out)',
  icon: CupertinoIcons.square_arrow_right,
  variant: VvcPillVariant.danger,
  size: VvcButtonSize.hero,
  onTap: () => _handleCheckOut(),
)
```

---

### 2.2 ប៊ូតុងរង្វង់មូល Header Action Pod (`VvcCirclePod`)
ធានារាងមូល ១:១ ពិតប្រាកដ (`BoxShape.circle`), មិនត្រូវ AppBar stretch ឱ្យត្រប៉ែត៖

```dart
// Back Button
VvcCirclePod.back(context, size: AppTokens.sizePodLarge)

// Add / Plus Button
VvcCirclePod.plus(size: AppTokens.sizePodLarge, onTap: _onAdd)

// Refresh Button
VvcCirclePod.refresh(size: AppTokens.sizePodLarge, onRefresh: _onRefresh)
```

---

### 2.3 ក្បាលទំព័រ ៣ កោះ (`VvcHeaderPodBar` ឬ `VvcAppBar`)

```dart
// ជម្រើសទី ១៖ ប្រើជាមួយ Scaffold(appBar: ...)
appBar: VvcAppBar(
  title: Text('ចំណងជើងទំព័រ'),
  actions: [
    IconButton(
      icon: const Icon(CupertinoIcons.add, size: 20),
      onPressed: _onAdd,
    ),
  ],
)

// ជម្រើសទី ២៖ ប្រើក្នុង Floating / Custom Scroll Scaffolds
VvcHeaderPodBar(
  isScrolled: _isScrolled,
  leading: VvcCirclePod.back(context),
  title: 'ការជូនដំណឹង',
  counterBadge: 5,
  actions: [
    VvcCirclePod.refresh(onRefresh: _refreshData),
  ],
)
```

---

### 2.4 របារស្វែងរក Full Capsule (`VvcSearchBar`)

```dart
VvcSearchBar(
  controller: _searchController,
  hintText: 'ស្វែងរក...',
  isScrolled: _isScrolled,
  onClear: () => setState(() {}),
)
```

---

### 2.5 Telegram Category Filter Tabs (`VvcFilterChips`)

```dart
VvcFilterChips(
  selectedKey: _selectedFilter,
  onSelected: (key) => setState(() => _selectedFilter = key),
  items: [
    VvcFilterItem(key: 'all', label: 'ទាំងអស់', count: 14),
    VvcFilterItem(key: 'unread', label: 'មិនទាន់អាន', count: 2),
    VvcFilterItem(key: 'read', label: 'បានអាន', count: 12),
  ],
)
```

---

### 2.6 ទិដ្ឋភាពទទេរស់រវើក (`VvcEmptyState` ជាមួយ Lottie Animation)

```dart
VvcEmptyState(
  useLottie: true, // ប្រើ animated vector lottie ស្វ័យប្រវត្ត
  title: 'រកមិនឃើញទិន្នន័យ',
  subtitle: 'សាកល្បងប្តូរពាក្យស្វែងរក ឬ Filter ផ្សេងទៀត',
  buttonLabel: 'បង្ហាញទាំងអស់',
  buttonIcon: CupertinoIcons.list_bullet,
  onButtonTap: () => _resetFilter(),
)
```

---

### 2.7 ចលនា Lottie Animations (`VvcLottie`)

```dart
// ១. ចលនា Checkmark ជោគជ័យ
VvcLottie.success(size: 90)

// ២. ចលនា Scanning Laser
VvcLottie.scanning(size: 120)

// ៣. ចលនា Empty Document Box
VvcLottie.empty(size: 110)

// ៤. ចលនា Notification Bell Ringing
VvcLottie.bell(size: 70)
```

---

## ៣. បញ្ជីត្រូវធ្វើ និងហាមដាច់ខាត (DOs & DONTs)

| ត្រូវធ្វើ (DO) ✅ | ហាមដាច់ខាត (DONT) ❌ |
| :--- | :--- |
| ប្រើ `VvcPillButton` សម្រាប់ប៊ូតុងទាំងអស់ | កុំសរសេរ `Container(decoration: BoxDecoration(borderRadius: BorderRadius.circular(12)))` សម្រាប់ប៊ូតុង |
| ប្រើ `AppTokens.radiusPill` (999.0) សម្រាប់ប៊ូតុង និង Tabs | កុំប្រើ radius ចតុកោណកែងស្ទើរមូលស្ទើរជ្រុងលើប៊ូតុង |
| រុំប៊ូតុងក្នុង `Center()` បើដាក់ក្នុង AppBar ដើម្បីការពារការ stretch | កុំញាត់ `VvcCirclePod` ចូលក្នុង `VvcAppBar` នាំឱ្យក្លាយជារង្វង់ត្រួតគ្នាច្រើនជាន់ |
| ប្រើ `TelegramBounce` សម្រាប់រាល់ការ Touch/Press | កុំប្រើ `InkWell` ឬ `GestureDetector` សុទ្ធដែលគ្មាន Spring Scale Feedback |
| ប្រើពុម្ពអក្សរ `Kantumruy Pro` សម្រាប់អក្សរខ្មែរ | កុំលាយពុម្ពអក្សរខ្មែរខុសគ្នាលើទំព័រតែមួយ |

