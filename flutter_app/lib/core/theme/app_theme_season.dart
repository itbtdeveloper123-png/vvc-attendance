enum AppThemeSeason {
  defaultHRM,
  khmerNewYear,
  chineseNewYear,
  pchumBen,
  waterFestival,
  bayonSpirit,
  angkorEmpire,
  romduolBloom,
  silverPagoda,
}

extension AppThemeSeasonExtension on AppThemeSeason {
  String get name {
    switch (this) {
      case AppThemeSeason.defaultHRM:
        return 'defaultHRM';
      case AppThemeSeason.khmerNewYear:
        return 'khmer_new_year';
      case AppThemeSeason.chineseNewYear:
        return 'chinese_new_year';
      case AppThemeSeason.pchumBen:
        return 'pchum_ben';
      case AppThemeSeason.waterFestival:
        return 'water_festival';
      case AppThemeSeason.bayonSpirit:
        return 'bayon_spirit';
      case AppThemeSeason.angkorEmpire:
        return 'angkor_empire';
      case AppThemeSeason.romduolBloom:
        return 'romduol_bloom';
      case AppThemeSeason.silverPagoda:
        return 'silver_pagoda';
    }
  }

  static AppThemeSeason fromString(String val) {
    switch (val) {
      case 'khmer_new_year':
        return AppThemeSeason.khmerNewYear;
      case 'chinese_new_year':
        return AppThemeSeason.chineseNewYear;
      case 'pchum_ben':
        return AppThemeSeason.pchumBen;
      case 'water_festival':
        return AppThemeSeason.waterFestival;
      case 'bayon_spirit':
        return AppThemeSeason.bayonSpirit;
      case 'angkor_empire':
        return AppThemeSeason.angkorEmpire;
      case 'romduol_bloom':
        return AppThemeSeason.romduolBloom;
      case 'silver_pagoda':
        return AppThemeSeason.silverPagoda;
      default:
        return AppThemeSeason.defaultHRM;
    }
  }

  String get displayName {
    switch (this) {
      case AppThemeSeason.khmerNewYear: return 'ចូលឆ្នាំខ្មែរ';
      case AppThemeSeason.chineseNewYear: return 'ចូលឆ្នាំចិន';
      case AppThemeSeason.pchumBen: return 'ភ្ជុំបិណ្ឌ';
      case AppThemeSeason.waterFestival: return 'បុណ្យអុំទូក';
      case AppThemeSeason.bayonSpirit: return 'ស្មារតីបាយ័ន';
      case AppThemeSeason.angkorEmpire: return 'អាណាចក្រអង្គរ';
      case AppThemeSeason.romduolBloom: return 'បុប្ផារំដួល';
      case AppThemeSeason.silverPagoda: return 'ព្រះវិហារប្រាក់';
      case AppThemeSeason.defaultHRM: return 'ធម្មតា (Default)';
    }
  }
}
