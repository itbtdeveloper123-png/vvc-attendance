// ========================================================
// LocalHrAssistantService
// ========================================================
// Offline-first AI HR Assistant Engine for VVC Attendance App.
// Provides instant, 100% free, offline HR policy knowledge,
// guidance, small talk, and intent classification in Khmer.
// ========================================================

class LocalHrResponse {
  final String text;
  final String category;
  final List<String> suggestedFollowUps;
  final bool isOfflineLocal;

  const LocalHrResponse({
    required this.text,
    required this.category,
    this.suggestedFollowUps = const [],
    this.isOfflineLocal = true,
  });
}

class LocalHrAssistantService {
  static final LocalHrAssistantService _instance =
      LocalHrAssistantService._internal();
  factory LocalHrAssistantService() => _instance;
  LocalHrAssistantService._internal();

  /// Main entry point: Processes user prompt and returns an AI HR response
  Future<LocalHrResponse> processQuery(String query, {String? userName}) async {
    final cleanQuery = query.trim().toLowerCase();

    // 1. Small Talk & Greetings
    final greetingResp = _checkGreetings(cleanQuery, userName);
    if (greetingResp != null) return greetingResp;

    // 2. Identity & About AI
    final identityResp = _checkIdentity(cleanQuery);
    if (identityResp != null) return identityResp;

    // 3. HR Category Intent Matching
    if (_matches(cleanQuery, ['សុំច្បាប់', 'ច្បាប់ឈប់', 'ឈប់សម្រាក', 'leave', 'sick', 'មាតុភាព', 'សម្រាកប្រចាំឆ្នាំ'])) {
      return _getLeavePolicyResponse();
    }

    if (_matches(cleanQuery, ['វត្តមាន', 'ស្កេន', 'scan', 'qr', 'face', 'ចូលយឺត', 'ចេញមុន', 'ភ្លេចស្កេន', 'late', 'attendance'])) {
      return _getAttendancePolicyResponse();
    }

    if (_matches(cleanQuery, ['ប្រាក់ខែ', 'ប្រាក់រង្វាន់', 'ot', 'ថែមម៉ោង', 'salary', 'payroll', 'payslip', 'ថ្លៃបាយ', 'ប្រាក់ឧបត្ថម្ភ'])) {
      return _getPayrollOtPolicyResponse();
    }

    if (_matches(cleanQuery, ['ម៉ោងធ្វើការ', 'ម៉ោងចូល', 'ម៉ោងចេញ', 'ថ្ងៃសីល', 'ថ្ងៃបុណ្យ', 'ថ្ងៃឈប់', 'working hours', 'schedule'])) {
      return _getWorkingHoursResponse();
    }

    if (_matches(cleanQuery, ['បេសកកម្ម', 'mission', 'ចុះបេសកកម្ម', 'ដំណើរកម្សាន្ត', 'រាយការណ៍'])) {
      return _getMissionPolicyResponse();
    }

    if (_matches(cleanQuery, ['ស្នើសុំ', 'សម្ភារ', 'ដកសម្ភារ', 'material', 'request', 'ទិញសម្ភារ'])) {
      return _getMaterialRequestResponse();
    }

    if (_matches(cleanQuery, ['គណនី', 'ប្តូរលេខសម្ងាត់', 'password', 'profile', 'ប្រវត្តិរូប', 'កែប្រែ'])) {
      return _getProfileAccountResponse();
    }

    if (_matches(cleanQuery, ['អរគុណ', 'thanks', 'thank you', 'ល្អណាស់', 'អរគុណច្រើន'])) {
      return const LocalHrResponse(
        text: '🙏 **ដោយសេចក្តីរីករាយ!** ខ្ញុំតែងតែនៅទីនេះដើម្បីជួយសម្រួលការងារ HR និងឆ្លើយរាល់ចម្ងល់របស់អ្នក។ ប្រសិនបើមានសំណួរផ្សេងទៀត សូមសួរខ្ញុំបានជានិច្ច! 😊',
        category: 'Thanks',
        suggestedFollowUps: ['របៀបសុំច្បាប់', 'ពិនិត្យម៉ោងធ្វើការ', 'ការសុំ OT'],
      );
    }

    // 4. Fallback for General / Out-of-Scope Queries
    return _getGeneralFallbackResponse(query);
  }

  bool _matches(String input, List<String> keywords) {
    return keywords.any((kw) => input.contains(kw));
  }

  LocalHrResponse? _checkGreetings(String q, String? name) {
    final greetings = ['សួស្ដី', 'សួស្តី', 'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'អរុណសួស្តី'];
    if (greetings.any((g) => q == g || q.startsWith('$g '))) {
      final displayName = (name != null && name.isNotEmpty) ? ' $name' : '';
      return LocalHrResponse(
        text: '👋 **ជម្រាបសួរ$displayName!**\n\nខ្ញុំគឺជា **AI HR Assistant (TFLite Engine)** របស់អ្នកជំនួយការផ្នែកធនធានមនុស្ស។ ខ្ញុំអាចជួយឆ្លើយសំណួរ និងផ្តល់ព័ត៌មានទាក់ទងនឹង៖\n\n'
            '• 📋 **ច្បាប់ឈប់សម្រាក** (សុំច្បាប់, ច្បាប់ជំងឺ, ច្បាប់ប្រចាំឆ្នាំ)\n'
            '• ⏰ **ការស្កេនវត្តមាន & OT** (ចូលយឺត, ភ្លេចស្កេន, ថែមម៉ោង)\n'
            '• 💰 **ព័ត៌មានប្រាក់ខែ & ថ្លៃឧបត្ថម្ភ**\n'
            '• 🚗 **ការចុះបេសកកម្ម & ស្នើសុំសម្ភារ**\n\n'
            'តើខ្ញុំអាចជួយអ្វីអ្នកបានដែរនៅថ្ងៃនេះ?',
        category: 'Greeting',
        suggestedFollowUps: [
          'តើរបៀបសុំច្បាប់ធ្វើដូចម្តេច?',
          'ព័ត៌មានអំពីការស្កេនវត្តមាន',
          'លក្ខខណ្ឌស្នើសុំ OT',
        ],
      );
    }
    return null;
  }

  LocalHrResponse? _checkIdentity(String q) {
    if (_matches(q, ['អ្នកជានរណា', 'who are you', 'ឈ្មោះអ្វី', 'តើអ្នកជាអ្វី', 'អ្នកណាបង្កើត'])) {
      return const LocalHrResponse(
        text: '🤖 **ខ្ញុំគឺជា AI HR Assistant** របស់ប្រព័ន្ធ VVC Attendance!\n\n'
            'ខ្ញុំត្រូវបានបង្កើតឡើងដោយបច្ចេកវិទ្យា **TFLite AI (On-Device Local Engine)** ដើម្បីជួយឆ្លើយសំណួរ ផ្តល់ព័ត៌មាន និងសម្រួលការងារផ្នែកធនធានមនុស្ស (HR) ជូនបុគ្គលិកទាំងអស់ដោយ **ឥតគិតថ្លៃ និង Offline 100%** ដោយមិនចាំបាច់មាន Internet ឡើយ។',
        category: 'Identity',
        suggestedFollowUps: ['តើអ្នកអាចធ្វើអ្វីបានខ្លះ?', 'របៀបសុំច្បាប់', 'ម៉ោងធ្វើការ'],
      );
    }
    return null;
  }

  LocalHrResponse _getLeavePolicyResponse() {
    return const LocalHrResponse(
      text: '📋 **គោលការណ៍ច្បាប់ឈប់សម្រាក (Leave Policy)**\n\n'
          '**១. ប្រភេទនៃច្បាប់ឈប់សម្រាក៖**\n'
          '• **ច្បាប់ប្រចាំឆ្នាំ (Annual Leave)៖** បុគ្គលិកមានសិទ្ធិឈប់សម្រាក ១៨ ថ្ងៃក្នុងមួយឆ្នាំ (១.៥ ថ្ងៃ/ខែ)។\n'
          '• **ច្បាប់ជំងឺ (Sick Leave)៖** ត្រូវមានលិខិតបញ្ជាក់ពីគ្រូពេទ្យផ្លូវការ។\n'
          '• **ច្បាប់ពិសេស/មាតុភាព (Maternity/Special Leave)៖** តាមគោលការណ៍ច្បាប់ការងារ។\n\n'
          '**២. របៀបស្នើសុំច្បាប់តាម App ៖**\n'
          '១. ចូលទៅកាន់ Menu **«ស្នើច្បាប់» (Leave Request)** លើអេក្រង់ដើម\n'
          '២. ជ្រើសរើសប្រកាសប្រភេទច្បាប់ និងកាលបរិច្ឆេទ (ចាប់ផ្តើម - បញ្ចប់)\n'
          '៣. បញ្ជាក់មូលហេតុ និងភ្ជាប់ឯកសារ (បើមាន)\n'
          '៤. ចុច **«បញ្ជូនសំណើ»** ដើម្បីផ្ញើទៅកាន់ប្រធានផ្នែកអនុម័ត។',
      category: 'Leave',
      suggestedFollowUps: ['ការពិនិត្យស្ថានភាពច្បាប់', 'ម៉ោងធ្វើការ', 'ការសុំ OT'],
    );
  }

  LocalHrResponse _getAttendancePolicyResponse() {
    return const LocalHrResponse(
      text: '⏰ **ការគ្រប់គ្រងវត្តមាន (Attendance & Scan Rules)**\n\n'
          '**១. វិធីស្កេនវត្តមាន៖**\n'
          '• **Face Scan (ស្កេនមុខ)៖** ប្រើប្រាស់ប្រព័ន្ធ AI សម្គាល់មុខនៅលើទូរសព្ទ\n'
          '• **QR Scan ៖** ស្កេន QR Code នៅទីតាំងក្រុមហ៊ុន ឬទីតាំងកំណត់\n\n'
          '**២. ករណីចូលយឺត / ភ្លេចស្កេន ៖**\n'
          '• ប្រសិនបើចូលយឺត ប្រព័ន្ធនឹងតម្រូវឱ្យបញ្ចូល **«មូលហេតុចូលយឺត»** មុនពេលបញ្ជូន។\n'
          '• ប្រសិនបើភ្លេចស្កេនវត្តមាន សូមចូលទៅកាន់ Menu **«ភ្លេចស្កេន» (Forget Scan)** ដើម្បីស្នើសុំកែប្រែវត្តមានឡើងវិញ។',
      category: 'Attendance',
      suggestedFollowUps: ['របៀបចុះឈ្មោះ Face ID', 'លក្ខខណ្ឌសុំ OT', 'របៀបសុំច្បាប់'],
    );
  }

  LocalHrResponse _getPayrollOtPolicyResponse() {
    return const LocalHrResponse(
      text: '💰 **គោលការណ៍ប្រាក់ខែ & ការធ្វើការថែមម៉ោង (Payroll & OT)**\n\n'
          '**១. ការធ្វើការថែមម៉ោង (OT) ៖**\n'
          '• ត្រូវមានការអនុញ្ញាតពីប្រធានគ្រប់គ្រងមុនពេលធ្វើ OT។\n'
          '• របៀបសុំ ៖ ចូលទៅកាន់ Menu **«ស្នើ OT»** រួចបញ្ជាក់ម៉ោងចាប់ផ្តើម បញ្ចប់ និងភារកិច្ច។\n\n'
          '**២. ព័ត៌មានប្រាក់ខែ (Payslip) ៖**\n'
          '• លោកអ្នកអាចពិនិត្យមើលរបាយការណ៍ប្រាក់ខែ និងប័ណ្ណទូទាត់នៅក្នុង Menu **«ប្រាក់ខែ» (Payroll)** ដោយសុវត្ថិភាព។',
      category: 'Payroll',
      suggestedFollowUps: ['របៀបស្នើ OT', 'ប្រវត្តិស្កេនវត្តមាន', 'របៀបសុំច្បាប់'],
    );
  }

  LocalHrResponse _getWorkingHoursResponse() {
    return const LocalHrResponse(
      text: '📅 **កាលវិភាគ & ម៉ោងធ្វើការ (Working Schedule)**\n\n'
          '• **ម៉ោងចូលធ្វើការពេលព្រឹក ៖** 08:00 AM\n'
          '• **ម៉ោងសម្រាកថ្ងៃត្រង់ ៖** 12:00 PM - 01:00 PM\n'
          '• **ម៉ោងចេញធ្វើការពេលល្ងាច ៖** 05:00 PM\n'
          '• **ថ្ងៃធ្វើការ ៖** ថ្ងៃច័ន្ទ ដល់ ថ្ងៃសៅរ៍ (តាមកាលវិភាគកំណត់)\n\n'
          '💡 *សម្គាល់ ៖ លោកអ្នកអាចមើលប្រតិទិនថ្ងៃសីល និងថ្ងៃឈប់សម្រាកបុណ្យជាតិនៅក្នុងទំព័រដើម ឬទំព័រ Profile។*',
      category: 'Schedule',
      suggestedFollowUps: ['ការស្កេនវត្តមាន', 'ការសុំច្បាប់', 'ការសុំ OT'],
    );
  }

  LocalHrResponse _getMissionPolicyResponse() {
    return const LocalHrResponse(
      text: '🚗 **ការចុះបេសកកម្ម (Mission Request)**\n\n'
          'ប្រសិនបើលោកអ្នកត្រូវចុះបេសកកម្មក្រៅទីតាំង ៖\n'
          '១. ចូលទៅកាន់ Menu **«បេសកកម្ម» (Mission)**\n'
          '២. បញ្ជាក់ទីតាំងគោលដៅ ថ្ងៃខែ និងគោលបំណងបេសកកម្ម\n'
          '៣. បញ្ជូនសំណើទៅកាន់ថ្នាក់ដឹកនាំអនុម័ត\n'
          '៤. នៅពេលដល់ទីតាំងបេសកកម្ម លោកអ្នកអាចស្កេនវត្តមានក្រៅផ្លូវការ (Outside Attendance) បាន។',
      category: 'Mission',
      suggestedFollowUps: ['របៀបស្កេនវត្តមាន', 'ការស្នើសុំសម្ភារ', 'របៀបសុំច្បាប់'],
    );
  }

  LocalHrResponse _getMaterialRequestResponse() {
    return const LocalHrResponse(
      text: '📦 **ការស្នើសុំសម្ភារប្រើប្រាស់ (Material Request)**\n\n'
          'លោកអ្នកអាចស្នើសុំសម្ភារការិយាល័យ ឬឧបករណ៍ការងារបានតាមរបៀប៖\n'
          '១. ចូលទៅកាន់ Menu **«ស្នើសុំសម្ភារ» (Material Request)**\n'
          '២. ជ្រើសរើសមុខទំនិញ/សម្ភារ និងចំនួនដែលត្រូវការ\n'
          '៣. បញ្ជាក់មូលហេតុនៃការប្រើប្រាស់ និងចុះហត្ថលេខាឌីជីថល (Digital Signature)\n'
          '៤. ចុចបញ្ជូនសំណើដើម្បីរង់ចាំការពិនិត្យពីផ្នែកឃ្លាំង/HR។',
      category: 'Material',
      suggestedFollowUps: ['របៀបសុំច្បាប់', 'ការចុះបេសកកម្ម', 'ព័ត៌មានប្រាក់ខែ'],
    );
  }

  LocalHrResponse _getProfileAccountResponse() {
    return const LocalHrResponse(
      text: '👤 **ការគ្រប់គ្រងគណនី (Account & Profile Settings)**\n\n'
          '• **ប្តូរលេខសម្ងាត់ ៖** ចូលទៅកាន់ទំព័រ «គណនី» (Profile) -> ចុច «ប្តូរលេខសម្ងាត់»\n'
          '• **ចុះឈ្មោះ Face ID ៖** ចូលទៅកាន់ទំព័រ «គណនី» -> ចុច «ចុះឈ្មោះផ្ទៃមុខ (Face Scan)»\n'
          '• **ប្តូរគណនី (Switch Account) ៖** ចូលទៅទំព័រ «គណនី» -> ចុច «ប្តូរគណនី»។',
      category: 'Profile',
      suggestedFollowUps: ['របៀបចុះឈ្មោះ Face ID', 'ការស្កេនវត្តមាន', 'អំពីប្រព័ន្ធ'],
    );
  }

  LocalHrResponse _getGeneralFallbackResponse(String query) {
    return const LocalHrResponse(
      text: '🤖 **ខ្ញុំគឺជា AI HR Assistant (Local Engine)**\n\n'
          'សុំទោសផង! ខ្ញុំឆ្លើយតបបានយ៉ាងល្អចំពោះសំណួរទាក់ទងនឹង **ធនធានមនុស្ស (HR), ច្បាប់ក្រុមហ៊ុន, វត្តមាន, ការសុំច្បាប់, និងប្រាក់ខែ**។\n\n'
          '💡 **លោកអ្នកអាចសួរខ្ញុំអំពី៖**\n'
          '• «តើរបៀបសុំច្បាប់ធ្វើដូចម្តេច?»\n'
          '• «ម៉ោងចូលធ្វើការ និងម៉ោងចេញ?»\n'
          '• «ការស្កេនវត្តមាន ឬការសុំ OT»\n'
          '• «របៀបស្នើសុំបេសកកម្ម ឬសម្ភារ»',
      category: 'General',
      suggestedFollowUps: [
        'របៀបសុំច្បាប់',
        'ព័ត៌មានស្កេនវត្តមាន',
        'ការសុំ OT',
      ],
    );
  }
}
