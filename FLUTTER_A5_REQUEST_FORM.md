# Flutter A5 Request Form Implementation

## ទិដ្ឋភាពសង្ខេប (Overview)

ឯកសារនេះពន្យល់អំពីការអនុវត្ត A5 paper format និង checkbox system សម្រាប់ request types ក្នុង Flutter mobile app។

## ឯកសារដែលបានបន្ថែម/កែប្រែ (Files Added/Modified)

### 1. **`lib/widgets/a5_paper_form.dart`** (New)
- A5 paper format widget សម្រាប់ Flutter
- Request type checkbox system
- A5 form section, row, field widgets
- Status badge widget
- Signature section widget

### 2. **`lib/screens/a5_request_form_screen.dart`** (New)
- Test screen សម្រាប់ A5 request form
- Sample data fill functionality
- Integration ជាមួយ User Provider
- Form validation និង submission

### 3. **`lib/widgets/dynamic_form_renderer.dart`** (Modified)
- បន្ថែម import `a5_paper_form.dart`
- បន្ថែម `request_type` field type support
- បន្ថែម `_buildRequestTypeField()` method

### 4. **`lib/screens/dynamic_form_screen.dart`** (Modified)
- បន្ថែម import `a5_paper_form.dart`
- Wrap DynamicFormRenderer ជាមួយ A5PaperForm widget
- បន្ថែម print និង back buttons

### 5. **`lib/screens/requests_screen.dart`** (Modified)
- បន្ថែម import `a5_request_form_screen.dart`
- បន្ថែម "A5 Request Form Test" menu item

## Widget Components

### A5PaperForm
Main widget សម្រាប់ A5 paper format:

```dart
A5PaperForm(
  title: 'សំណើសុំសេវា',
  subtitle: 'SERVICE REQUEST FORM',
  onPrint: () {
    // Print functionality
  },
  onBack: () {
    Navigator.pop(context);
  },
  child: YourFormContent(),
)
```

### A5FormSection
Widget សម្រាប់ form section:

```dart
A5FormSection(
  title: 'ប្រភេទសំណើ (Request Type)',
  icon: Icons.list_check,
  isRequired: true,
  children: [
    // Section content
  ],
)
```

### A5RequestTypeCheckboxGroup
Checkbox group សម្រាប់ request types:

```dart
A5RequestTypeCheckboxGroup(
  selectedValue: _selectedRequestType,
  onChanged: (value) {
    setState(() {
      _selectedRequestType = value;
    });
  },
)
```

### Request Types ដែលបានគាំទ្រ (Supported Request Types)

1. **leave** - ច្បាប់ (Leave) - `Icons.calendar_today`
2. **late** - មកយឺត (Late) - `Icons.access_time`
3. **forgotten_scan** - ភ្លេចស្កេន (Forgotten Scan) - `Icons.fingerprint`
4. **deo** - ដេអូស (DEO) - `Icons.exit_to_app`

## A5 Paper Specifications

### Physical Dimensions
- **Width**: 148mm
- **Height**: 210mm
- **Aspect Ratio**: 1:1.414

### Flutter Implementation
- **Container**: Rounded corners (8px)
- **Shadow**: Subtle drop shadow
- **Padding**: 16px content padding
- **Font Size**: 12px body text, 14px labels

## Mobile Responsive Design

### Layout Strategy
- **Single Column**: លើ mobile screens
- **Responsive Widgets**: Auto-adjust based on screen size
- **Touch-Friendly**: Minimum 44px touch targets
- **Scrollable**: SingleChildScrollView សម្រាប់ small screens

### Breakpoints
- **Mobile**: < 768px (default mobile layout)
- **Tablet**: 768px - 1024px (adjusted spacing)
- **Desktop**: > 1024px (max width container)

## Checkbox System Features

### Single Selection
- អាចជ្រើសរើសតែមួយ request type ប៉ុណ្ណោះ
- Auto-uncheck ប្រភេទផ្សេងទៀតនៅពេលជ្រើសរើសថ្មី

### Visual Feedback
- **Selected State**: Primary color background
- **Unselected State**: White background with border
- **Icon Display**: Icon សម្រាប់ប្រភេទនីមួយៗ
- **Text Color**: White (selected) / Primary (unselected)

### Grid Layout
- **2 Columns**: សម្រាប់ checkbox grid
- **Aspect Ratio**: 2.5 (width:height)
- **Spacing**: 8px gap between items

## Integration with Existing System

### User Provider Integration
Auto-fill user information ពី UserProvider:

```dart
final user = Provider.of<UserProvider>(context);
user.name        // ឈ្មោះបុគ្គលិក
user.employeeId  // លេខសម្គាល់
user.department  // ផ្នែក
user.position    // មុខតំណែង
```

### Dynamic Form Integration
Request type field អាចត្រូវបានប្រើក្នុង Dynamic Form Builder:

```dart
FormField(
  fieldType: 'request_type',
  fieldName: 'request_type',
  fieldLabel: 'ប្រភេទសំណើ',
  required: true,
)
```

## Testing Instructions

### 1. Open Test Screen
Navigate to: Requests Screen → "A5 Request Form Test"

### 2. Test Checkbox Functionality
- ចុចលើ request type នីមួយៗ
- ពិនិត្យថា single selection ដំណើរការ
- ពិនិត្យ visual feedback

### 3. Test Sample Data
- ចុច "បំពេញទិន្នន័យឧទាហរណ៍" button
- ពិនិត្យថា data ត្រូវបាន fill ត្រឹមត្រូវ
- ពិនិត្យ checkbox selection

### 4. Test Clear Functionality
- ចុច "សម្អាត" button
- ពិនិត្យថា form ត្រូវបាន clear

### 5. Test Responsive Layout
- Test លើ different screen sizes
- Test លើ mobile, tablet, desktop
- ពិនិត្យ scroll និង layout

## Customization Options

### Colors
ប្តូរពណ៌តាម `AppTheme`:

```dart
// In app_theme.dart
static const Color primary = Color(0xFF667eea);
static const Color fieldFill = Color(0xFFF8F9FA);
static const Color fieldBorder = Color(0xFFE9ECEF);
```

### Request Types
បន្ថែម request types ថ្មីក្នុង `A5RequestTypeCheckboxGroup`:

```dart
static const Map<String, _RequestTypeInfo> _requestTypes = {
  'new_type': _RequestTypeInfo(
    value: 'new_type',
    label: 'New Type (Khmer)',
    icon: Icons.icon_name,
  ),
  // ... existing types
};
```

### Font Sizes
ប្តូរ font sizes ក្នុង widget classes:

```dart
// Header
fontSize: 20  // Title
fontSize: 12  // Subtitle

// Body
fontSize: 12  // Labels
fontSize: 12  // Values
fontSize: 10  // Status badges
```

## Print Functionality

បច្ចុប្បន្ននេះ print functionality គឺ placeholder:

```dart
onPrint: () {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text('បោះពុម្ព functionality នឹងត្រូវបានបន្ថែមនៅពេលក្រោយ'),
    ),
  );
}
```

### Future Print Implementation
អាចប្រើ packages:
- `printing` - សម្រាប់ PDF generation
- `pdf` - សម្រាប់ PDF creation
- `share_plus` - សម្រាប់ share/print options

## Performance Considerations

### Widget Optimization
- `const` constructors សម្រាប់ static widgets
- `setState` តែពេលចាំបាច់
- `dispose` controllers properly

### Memory Management
- Dispose TextEditingController ក្នុង dispose()
- Dispose SignatureController ក្នុង dispose()
- Clear large data structures

## Known Limitations

1. **Print Functionality**: នៅតែជា placeholder
2. **PDF Export**: មិនទាន់បានអនុវត្ត
3. **Digital Signature**: មិនទាន់បញ្ចូល signature capture
4. **Offline Support**: ត្រូវការ internet សម្រាប់ fonts

## Future Enhancements

1. **PDF Export** - Export form ទៅ PDF format
2. **Digital Signature** - Signature capture widget
3. **Offline Mode** - Cache forms សម្រាប់ offline use
4. **Multi-language** - Support ភាសាច្រើន
5. **Form Templates** - Save/load custom templates
6. **Barcode/QR** - Add barcode ឬ QR code
7. **Validation** - Advanced form validation
8. **Attachments** - File upload support

## Troubleshooting

### Checkbox Not Working
- ពិនិត្យថា `onChanged` callback ត្រូវបាន set
- ពិនិត្យ `setState()` ត្រូវបាន call
- ពិនិត្យ `selectedValue` matching

### Layout Issues
- ពិនិត្យ screen size breakpoints
- ពិនិត្យ padding និង margins
- Test លើ different devices

### User Data Not Loading
- ពិនិត្យ UserProvider initialization
- ពិនិត្យ user authentication state
- ពិនិត្យ data availability

## Browser Compatibility

Flutter apps ដំណើរការលើ:
- ✅ Android 5.0+
- ✅ iOS 12.0+
- ✅ Web (Chrome, Firefox, Safari, Edge)
- ✅ Windows, macOS, Linux (Desktop)

## Support & Maintenance

សម្រាប់ការគាំទ្រ ឬសំណើ:
- ពិនិត្យ `REQUEST_FORM_IMPLEMENTATION.md` (Web version)
- ពិនិត្យ `FORM_BUILDER_README.md`
- ពិនិត្យ `AGENTS.md`
- ទាក់ទង Flutter team ឬ development team

---

**Version**: 1.0  
**Last Updated**: 2026-07-29  
**Author**: Devin AI Assistant  
**Platform**: Flutter (Mobile, Web, Desktop)