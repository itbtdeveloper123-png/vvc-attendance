# Form Builder System - Complete Documentation

## ទិដ្ឋភាពសង្ខេប (Overview)

Form Builder System គឺជាប្រព័ន្ធដែលអនុញ្ញាតឱ្យអ្នកគ្រប់គ្រងបង្កើត Form សំណើ ឬលិខិតបេសកម្មដោយប្រើ Drag & Drop ដោយមិនចាំបាច់សរសេរកូដ។

## សមាសភាពដែលបានបង្កើត (Components Created)

### 1. Database Schema (`form_builder_schema.sql`)
- **form_templates**: រក្សាទុកព័ត៌មាន Form Templates
- **form_fields**: រក្សាទុក Fields នីមួយៗនៃ Template
- **form_submissions**: រក្សាទុកទិន្នន័យដែលបានដាក់ស្នើ

### 2. API Endpoints (`form_builder_api.php`)
- **GET/POST/PUT/DELETE**: គ្រប់គ្រង Form Templates
- **GET/POST/PUT/DELETE**: គ្រប់គ្រង Form Fields
- **GET/POST**: គ្រប់គ្រង Form Submissions
- **PUT**: កែប្រែស្ថានភាពសំណើ (approved/rejected)

### 3. Admin Panel UI (`form_builder.php`)
- **Drag & Drop Interface**: ទាញ Field Types ពី sidebar មកដាក់ក្នុង canvas
- **Field Types**: Text, Number, Email, Date, Select, Textarea, Checkbox, File, Signature, Branch, Department, Position
- **Property Editor**: កែប្រែ field properties (label, placeholder, required, validation)
- **Template Management**: បង្កើត, កែប្រែ, លុប, duplicate templates
- **Real-time Preview**: មើលរូបរាង Form កំឡុងពេលបង្កើត

### 4. Flutter App Components

#### Models (`lib/models/form_template.dart`)
- `FormTemplate`: គំរូទិន្នន័យ Template
- `FormField`: គំរូទិន្នន័យ Field
- `FieldOption`: ជម្រើសសម្រាប់ Select fields
- `FormSubmission`: គំរូទិន្នន័យ Submission

#### Service (`lib/services/form_builder_service.dart`)
- API calls ទាំងអស់សម្រាប់ Form Builder
- Handle CRUD operations សម្រាប់ templates, fields, submissions

#### Dynamic Form Renderer (`lib/widgets/dynamic_form_renderer.dart`)
- Render Form តាម Template ដោយស្វ័យប្រវត្តិ
- Support គ្រប់ Field Types
- Validation តាម Field rules
- Signature capture
- File upload

#### Dynamic Form Screen (`lib/screens/dynamic_form_screen.dart`)
- Screen សម្រាប់បង្ហាញ Dynamic Form
- Handle form submission
- Integration ជាមួយ User Provider

## របៀបប្រើប្រាស់ (How to Use)

### 1. ដំឡើង Database (Installation)

```bash
# Import database schema
mysql -u username -p database_name < form_builder_schema.sql
```

### 2. ដំឡើង Admin Panel

```bash
# Copy files to server
cp form_builder_api.php /path/to/server/
cp form_builder.php /path/to/server/
```

### 3. ចូលប្រើ Form Builder

```
http://your-server.com/form_builder.php
```

### 4. បង្កើត Form Template ថ្មី

1. ចុច "បង្កើត Template ថ្មី"
2. បញ្ចូលឈ្មោះ, ការពិពណ៌នា, និងប្រភេទ
3. ទាញ Field Types ពី sidebar មកដាក់ក្នុង canvas
4. កែប្រែ field properties តាមតម្រូវការ
5. ចុច "រក្សាទុក"

### 5. ប្រើក្នុង Flutter App

```dart
// Navigate to dynamic form
Navigator.push(
  context,
  MaterialPageRoute(
    builder: (context) => DynamicFormScreen(
      templateId: 1, // Template ID from database
    ),
  ),
);
```

## Field Types ដែលអាចប្រើបាន

| Field Type | Description | Usage |
|------------|-------------|-------|
| Text | បញ្ចូលអត្ថបទធម្មតា | ឈ្មោះ, អាសយដ្ឋាន |
| Number | បញ្ចូលលេខ | ទូរស័ព្ទ, ចំនួន |
| Email | បញ្ចូល Email | អ៊ីមែល |
| Date | ជ្រើសរើសថ្ងៃ | ថ្ងៃខែឆ្នាំ |
| Select | ជ្រើសរើសពីជម្រើស | ផ្នែក, មុខតំណែង |
| Textarea | បញ្ចូលអត្ថបទវែង | មូលហេតុ |
| Checkbox | ជ្រើសរើស yes/no | ការយល់ព្រម |
| File | ដាក់ឯកសារ | រូបភាព, PDF |
| Signature | ហត្ថលេខា | ហត្ថលេខាឌីជីថល |
| Branch | សាខា (auto) | ពី User Profile |
| Department | ផ្នែក (auto) | ពី User Profile |
| Position | មុខតំណែង (auto) | ពី User Profile |

## API Endpoints

### Templates
- `GET /form_builder_api.php?action=get_templates`
- `GET /form_builder_api.php?action=get_template&id={id}`
- `POST /form_builder_api.php?action=create_template`
- `PUT /form_builder_api.php?action=update_template`
- `DELETE /form_builder_api.php?action=delete_template&id={id}`

### Fields
- `GET /form_builder_api.php?action=get_fields&template_id={id}`
- `POST /form_builder_api.php?action=create_field`
- `PUT /form_builder_api.php?action=update_field`
- `DELETE /form_builder_api.php?action=delete_field&id={id}`
- `POST /form_builder_api.php?action=reorder_fields`

### Submissions
- `GET /form_builder_api.php?action=get_submissions`
- `POST /form_builder_api.php?action=create_submission`
- `PUT /form_builder_api.php?action=update_submission_status`

## លក្ខណៈពិសេស (Features)

### Admin Panel
- ✅ Drag & Drop Interface
- ✅ Real-time Form Preview
- ✅ Field Property Editor
- ✅ Template Management
- ✅ Khmer Font Support (Koulen, Battambang)
- ✅ Responsive Design

### Flutter App
- ✅ Dynamic Form Rendering
- ✅ Field Validation
- ✅ Signature Capture
- ✅ File Upload
- ✅ Auto-populate User Data
- ✅ Offline Support (Future)

## ការអភិវឌ្ឍន៍បន្ត៍ (Future Enhancements)

- [ ] Form Preview Modal in Admin Panel
- [ ] Form Analytics & Reports
- [ ] Email Notifications
- [ ] Form Versioning
- [ ] Conditional Fields
- [ ] Form Templates Library
- [ ] Multi-language Support
- [ ] Offline Mode for Flutter App

## ការដោះស្រាយបញ្ហា (Troubleshooting)

### Database Connection Error
- ពិនិត្យ `config.php` connection settings
- ប្រាកដថា database tables ត្រូវបានបង្កើត

### API Not Responding
- ពិនិត្យ PHP error logs
- ប្រាកដថា file permissions ត្រឹមត្រូវ

### Flutter Form Not Loading
- ពិនិត្យ API base URL
- ពិនិត្យ network connection
- ពិនិត្យ authentication token

## ការគាំទ្រ (Support)

សម្រាប់ការគាំទ្រ ឬសំណួរណាមួយ សូមទាក់ទង development team។

---

**Version**: 1.0.0  
**Last Updated**: 2026-07-26  
**License**: Proprietary
