# Form Builder Troubleshooting Guide

## "Failed to load templates" Error Resolution

បើសិនជាអ្នកបានឃើញ error "Failed to load templates" នៅក្នុង Form Builder, សូមធ្វើតាមជំហានទាំងនេះ:

## Step 1: Check Database Tables

### Method 1: Using phpMyAdmin
1. បើក phpMyAdmin
2. ជ្រើសរើស database របស់អ្នក
3. ពិនិត្យថា tables ទាំងនេះមាន:
   - `form_templates`
   - `form_fields`
   - `form_submissions`

### Method 2: Using Check Script
1. បើក browser រួចទៅកាន់: `http://your-server.com/check_form_builder_setup.php`
2. ពិនិត្យ results នៅក្នុង "Database Tables Check" section
3. បើ tables ខកខាន, សូមធ្វើ Step 2

## Step 2: Create Missing Tables

បើ tables មិនទាន់មាន, សូម run SQL script:

```bash
# Using command line
mysql -u username -p database_name < form_builder_schema.sql

# Or using phpMyAdmin
# 1. បើក phpMyAdmin
# 2. ជ្រើសរើស database
# 3. ចុច "Import" tab
# 4. ជ្រើសរើស file form_builder_schema.sql
# 5. ចុច "Go"
```

## Step 3: Check File Permissions

ប្រាកដថា files ទាំងនេះអាចត្រូវបានអានដោយ web server:
- `form_builder.php`
- `form_builder_api.php`
- `config.php`

```bash
# On Linux/Unix
chmod 644 form_builder.php
chmod 644 form_builder_api.php
chmod 644 config.php
```

## Step 4: Check Database Connection

ពិនិត្យថា database connection ក្នុង `config.php` ត្រឹមត្រូវ:

```php
// In config.php
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'your_username');
define('DB_PASSWORD', 'your_password');
define('DB_NAME', 'your_database');
```

## Step 5: Test API Directly

Test API endpoint ដោយផ្ទាល់:

```bash
# Using curl
curl "http://your-server.com/form_builder_api.php?action=get_templates"

# Or open in browser
http://your-server.com/form_builder_api.php?action=get_templates
```

**Expected Response:**
```json
{
  "success": true,
  "message": "Templates retrieved successfully",
  "data": []
}
```

**Error Response Examples:**
```json
{
  "success": false,
  "message": "Database connection failed"
}
```

```json
{
  "success": false,
  "message": "Required table 'form_templates' does not exist"
}
```

## Step 6: Check Browser Console

1. បើក Form Builder page
2. ចុច F12 ឬ right-click → Inspect
3. ទៅ Console tab
4. រកមើល error messages

### Common Console Errors:

**CORS Error:**
```
Access to XMLHttpRequest at 'form_builder_api.php' from origin 'null' has been blocked by CORS policy
```
**Solution:** Check CORS headers in `form_builder_api.php`

**Network Error:**
```
Failed to load resource: net::ERR_CONNECTION_REFUSED
```
**Solution:** Check server is running and file path is correct

**JavaScript Error:**
```
ReferenceError: $ is not defined
```
**Solution:** Check jQuery is loaded properly

## Step 7: Clear Browser Cache

1. ចុច Ctrl+Shift+Delete (Windows) ឬ Cmd+Shift+Delete (Mac)
2. ជ្រើសរើស "Cached images and files"
3. ចុច "Clear data"
4. ផ្ទុក page ឡើងវិញ

## Step 8: Check PHP Error Log

```bash
# Check PHP error log
tail -f php_debug.log

# Or check server error log
tail -f /var/log/apache2/error.log  # Apache
tail -f /var/log/nginx/error.log     # Nginx
```

## Step 9: Verify Session

Form Builder ត្រូវការ admin session:

```php
// Check if admin is logged in
session_start();
if (!isset($_SESSION['admin_id'])) {
    header('Location: admin_attendance.php?page=login');
    exit;
}
```

## Step 10: Test with Sample Data

បើគ្មាន templates, សូមបង្កើត sample template:

```sql
INSERT INTO form_templates (name, description, category, status, created_by) 
VALUES ('Test Template', 'This is a test template', 'request', 'active', 1);
```

## Recent Improvements Made

### 1. Enhanced Error Handling
- Console logging សម្រាប់ debugging
- Detailed error messages ក្នុង JavaScript
- Better error responses ពី API

### 2. Database Validation
- Auto-check required tables នៅពេល API load
- Graceful error handling សម្រាប់ missing tables
- Proper error logging

### 3. Improved JavaScript
- Null checks សម្រាប់ DOM elements
- Try-catch blocks សម្រាប់ Sortable initialization
- Better loading state management

## Quick Fix Checklist

- [ ] Database tables exist (`form_templates`, `form_fields`, `form_submissions`)
- [ ] Database connection is working
- [ ] File permissions are correct
- [ ] API endpoint is accessible
- [ ] No browser console errors
- [ ] Admin session is active
- [ ] Browser cache is cleared
- [ ] PHP error log shows no critical errors

## Contact Support

បើបញ្ហានៅតែមាន:
1. រក្សាទុក console error messages
2. រក្សាទុក API response
3. រក្សាទុក PHP error log entries
4. ទាក់ទង development team ជាមួយ information ទាំងនេះ

## Additional Resources

- **Form Builder README**: `FORM_BUILDER_README.md`
- **Setup Check Script**: `check_form_builder_setup.php`
- **Database Schema**: `form_builder_schema.sql`

---

**Last Updated**: 2026-07-29  
**Version**: 1.0