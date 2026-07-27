# Theme-Specific App Icons

This directory contains app icons for different seasonal themes, similar to Acleda Bank's seasonal icon system.

## Directory Structure

```
assets/icons/themes/
├── README.md
├── default_icon.png          # Default/General theme icon
├── khmer_new_year_icon.png    # Khmer New Year theme icon
├── pchum_ben_icon.png         # Pchum Ben theme icon
├── water_festival_icon.png    # Water Festival theme icon
├── christmas_icon.png         # Christmas theme icon
├── valentine_icon.png         # Valentine theme icon
├── smart_glass_icon.png      # Smart Glass theme icon
├── lunar_icon.png             # Lunar theme icon
└── bayon_spirit_icon.png     # Bayon Spirit theme icon
```

## Icon Specifications

- **Size**: 1024x1024 pixels (PNG format)
- **Format**: PNG with transparency
- **Background**: Transparent (for adaptive icons)
- **Style**: Should match the theme's color scheme and mood

## Theme Color Palettes (for icon design)

### Default/HRM Theme
- Primary: #6366F1 (Indigo)
- Secondary: #4F46E5
- Accent: #818CF8

### Khmer New Year Theme
- Primary: #EAB308 (Gold)
- Secondary: #CA8A04
- Accent: #FEF08A

### Pchum Ben Theme
- Primary: #9333EA (Purple)
- Secondary: #7E22CE
- Accent: #D8B4FE

### Water Festival Theme
- Primary: #0284C7 (Blue)
- Secondary: #0369A1
- Accent: #7DD3FC

### Christmas Theme
- Primary: #DC2626 (Red)
- Secondary: #991B1B
- Accent: #FCA5A5

### Valentine Theme
- Primary: #DB2777 (Pink)
- Secondary: #9D174D
- Accent: #F9A8D4

### Smart Glass Theme
- Primary: #94A3B8 (Silver/Slate)
- Secondary: #475569
- Accent: #E2E8F0

### Lunar Theme
- Primary: #1F4B99 (Bayon Blue)
- Secondary: #15346A
- Accent: #6391E2

### Bayon Spirit Theme
- Primary: #D4AF37 (Royal Gold)
- Secondary: #A6892C
- Accent: #FDE68A

## Implementation Notes

1. Icons should be placed in this directory
2. The app icon service will dynamically select the appropriate icon based on the active theme
3. Icons can be previewed in the Admin Theme Management panel
4. For iOS: Icons need to be processed through flutter_launcher_icons
5. For Android: Icons need to be placed in appropriate res/mipmap directories

## How to Add New Icons

1. Create a PNG icon (1024x1024) matching the theme's color scheme
2. Save it with the appropriate name in this directory
3. Update the BackendTheme model in `lib/services/theme_service.dart` to reference the new icon
4. The app will automatically use the new icon when the theme is activated

## Icon Preview in Admin Panel

Icons can be previewed in the Admin Theme Management panel by:
1. Navigate to Settings → Theme Management
2. Click on a theme to see its preview
3. The icon will be displayed alongside other theme assets
