# Request Form Implementation - Documentation

## ទិដ្ឋភាពសង្ខេប (Overview)

ឯកសារនេះពន្យល់អំពីការអនុវត្ត Request Form ដែលមាន:
- A5 paper size styling សម្រាប់បោះពុម្ព
- Mobile responsive design សម្រាប់ទូរសព្ទ
- Checkbox system សម្រាប់ជ្រើសរើសប្រភេទសំណើ

## ឯកសារដែលបានបង្កើត (Files Created)

### 1. `assets/css/form_print.css`
- CSS styling សម្រាប់ A5 paper size printing
- Mobile responsive design សម្រាប់ទូរសព្ទ, tablet, និង desktop
- Checkbox styling សម្រាប់ request type selection
- Signature section styling
- Status badge styling

### 2. `request_form_template.php`
- Request form template ដោយប្រើប្រាស់ checkbox system
- ប្រើបានតាម A5 paper size (148mm x 210mm)
- Mobile responsive design
- Auto-fill កាលបរិច្ឆេទបច្ចុប្បន្ន
- Print functionality

### 3. `request_form_test.php`
- Test page សម្រាប់សាកល្បង request form
- Sample data fill functionality
- Screen size indicator
- User details auto-fill ពី database

### 4. `form_builder.php` (Updated)
- បន្ថែម "Request Type" field type ទៅក្នុង form builder
- CSS styling សម្រាប់ request type checkbox group
- Preview functionality សម្រាប់ request type checkboxes

## ប្រភេទសំណើ (Request Types)

ប្រព័ន្ធនេះគាំទ្រប្រភេទសំណើ ៤ ប្រភេទ:

1. **ច្បាប់ (Leave)** - សំណើសុំច្បាប់ឈប់សម្រាក
2. **មកយឺត (Late)** - សំណើសុំមកធ្វើការយឺត
3. **ភ្លេចស្កេន (Forgotten Scan)** - សំណើសុំភ្លេចស្កេនមេដៃ
4. **ដេអូស (DEO)** - សំណើសុំចូលថ្មីដេអូស

## របៀបប្រើប្រាស់ (How to Use)

### 1. បើក Test Page
```
http://your-server.com/request_form_test.php
```

### 2. ប្រើប្រាស់ Form Builder
1. ចូលទៅ Form Builder: `http://your-server.com/form_builder.php`
2. ទាញ "Request Type" field ពី sidebar មកដាក់ក្នុង canvas
3. កែប្រែ field properties តាមតម្រូវការ
4. រក្សាទុក template

### 3. បោះពុម្ព Form (Print Form)
1. ចុច "បោះពុម្ព (Print)" button
2. ជ្រើសរើស A5 paper size ក្នុង print settings
3. បោះពុម្ព

## A5 Paper Size Specifications

- **Width**: 148mm
- **Height**: 210mm
- **Margin**: 10mm
- **Font Size**: 11pt
- **Line Height**: 1.4

## Mobile Responsive Breakpoints

### Mobile (≤ 768px)
- Single column layout
- Touch-friendly checkboxes (20px x 20px)
- Font size: 14px
- Padding: 15px

### Tablet (769px - 1024px)
- Two column layout
- Checkbox size: 18px x 18px
- Font size: 13px
- Padding: 20px

### Desktop (≥ 1025px)
- Multi-column layout
- Checkbox size: 18px x 18px
- Font size: 12px
- Padding: 30px

## Checkbox System Features

### Single Selection
- អាចជ្រើសរើសតែមួយ request type ប៉ុណ្ណោះ
- Auto-uncheck ប្រភេទផ្សេងទៀតនៅពេលជ្រើសរើសថ្មី

### Visual Feedback
- Highlighted state នៅពេលត្រូវបានជ្រើសរើស
- Icon display សម្រាប់ប្រភេទនីមួយៗ
- Color coding សម្រាប់ស្ថានភាព

## Integration with Existing System

### Database Integration
Request form អាចត្រូវបានភ្ជាប់ជាមួយ:
- `users` table - សម្រាប់ employee information
- `requests` table - សម្រាប់ request submissions
- `form_templates` table - សម្រាប់ custom form templates

### API Integration
Form data អាចត្រូវបានផ្ញើទៅ:
- `form_builder_api.php` - សម្រាប់ form submissions
- Custom endpoints - សម្រាប់ request processing

## Customization Options

### CSS Variables
```css
:root {
    --primary: #667eea;
    --primary-dark: #5568d3;
    --secondary: #764ba2;
    --success: #16a34a;
    --warning: #d97706;
    --danger: #dc2626;
}
```

### Request Type Customization
អាចបន្ថែមប្រភេទសំណើថ្មីក្នុង:
- `request_form_template.php`
- `form_builder.php`
- `assets/css/form_print.css`

## Testing Instructions

### 1. Desktop Testing
- បើក test page លើ desktop browser
- សាកល្បង checkbox selection
- សាកល្បង print preview (A5 size)
- សាកល្បង responsive resize

### 2. Mobile Testing
- បើក test page លើ mobile browser
- សាកល្បង touch interaction
- សាកល្បង layout លើអេក្រង់តូច
- សាកល្បង checkbox size

### 3. Print Testing
- សាកល្បង print លើ A5 paper
- ពិនិត្យ layout និង font size
- សាកល្បង signature section
- ពិនិត្យ margin និង spacing

## Browser Compatibility

- Chrome/Edge: ✅ Full support
- Firefox: ✅ Full support
- Safari: ✅ Full support
- Mobile browsers: ✅ Full support

## Known Limitations

1. **Print Preview**: អាចមានភាពខុសគ្នារវាង browsers
2. **Mobile Print**: មុខងារ print លើ mobile អាចមានកំរិតខុសគ្នា
3. **Custom Fonts**: ត្រូវការ internet connection សម្រាប់ Google Fonts

## Future Enhancements

1. **Digital Signature** - បន្ថែម digital signature capture
2. **QR Code** - បន្ថែម QR code លើ form
3. **Multi-language** - គាំទ្រភាសាច្រើន
4. **Auto-save** - Save form data ដោយស្វ័យប្រវត្តិ
5. **PDF Export** - Export ទៅ PDF format

## Support & Maintenance

សម្រាប់ការគាំទ្រ ឬសំណើ:
- ពិនិត្យមើល `FORM_BUILDER_README.md`
- ពិនិត្យមើល `AGENTS.md`
- ទាក់ទងអ្នកគ្រប់គ្រង system

---

**Version**: 1.0  
**Last Updated**: 2026-07-29  
**Author**: Devin AI Assistant