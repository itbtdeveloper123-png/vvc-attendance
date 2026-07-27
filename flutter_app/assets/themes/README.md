# Theme Assets Directory

This directory contains assets for different app themes.

## Theme Structure

Each theme should have its own folder with the following structure:

```
themes/
├── khmer_new_year/
│   ├── background.png
│   ├── app_icon.png
│   ├── splash.png
│   └── preview.png
├── pchum_ben/
│   ├── background.png
│   ├── app_icon.png
│   ├── splash.png
│   └── preview.png
├── water_festival/
│   ├── background.png
│   ├── app_icon.png
│   ├── splash.png
│   └── preview.png
└── ...
```

## Theme Guidelines

1. **Background Images**: Should be high quality, suitable for mobile screens (recommend 1080x1920px)
2. **App Icons**: Should be 512x512px PNG format with transparency
3. **Splash Screens**: Should match the theme's visual style (recommend 1080x1920px)
4. **Preview Images**: Small thumbnails for theme selection (recommend 200x200px)

## Color Guidelines

### Khmer New Year (បុណ្យចូលឆ្នាំខ្មែរ)
- Primary: Gold (#EAB308)
- Secondary: Red (#DC2626) 
- Accent: Green (#16A34A)
- Background: Warm tones

### Pchum Ben (បុណ្យភ្ជុំបិណ្ឌ)
- Primary: Purple (#9333EA)
- Secondary: Gold (#F59E0B)
- Accent: Dark (#1F2937)
- Background: Dark, spiritual tones

### Water Festival (បុណ្យអុំទូក)
- Primary: Blue (#0284C7)
- Secondary: Cyan (#06B6D4)
- Accent: Orange (#F59E0B)
- Background: Water-inspired blues

### Christmas (បុណ្យណូអែល)
- Primary: Red (#DC2626)
- Secondary: Green (#16A34A)
- Accent: Gold (#F59E0B)
- Background: Festive red/green

### Valentine (បុណ្យស្នេហ៍)
- Primary: Pink (#EC4899)
- Secondary: Rose (#F43F5E)
- Accent: Purple (#9333EA)
- Background: Romantic pinks

## Adding New Themes

1. Create a new folder for your theme
2. Add the required assets (background, icon, splash, preview)
3. Update the theme configuration in the database via Admin Panel
4. Test the theme on different devices

## Notes

- Theme assets are loaded from the server URLs configured in the database
- Local assets in this folder can be used for development and testing
- For production, assets should be hosted on the server for faster loading