# Khmer OCR Feature Documentation

លក្ខណសម្ព័ន្ធថ្មីសម្រាប់ការស្តាប់អក្សរខ្មែរ (Khmer OCR) ពីឯកសារដោយប្រើ Google Gemini 1.5 Flash API

## ផ្នែកទី ១: PHP Backend API

### ឯកសារ៖ `api/ocr-khmer.php`

នេះគឺជា PHP REST API endpoint ដែលដំណើរការរូបភាពឯកសារ និងស្រង់អក្សរខ្មែរដោយប្រើ **Google Gemini 1.5 Flash API**។

### អ្វីទៅ Google Gemini 1.5 Flash API?

Gemini 1.5 Flash គឺជា AI model ដែលមាន capability ក្នុងការស្តាប់អក្សរ (OCR) ដោយខ្លាំងជាងមុន សម្រាប់ភាសាខ្មែរ។ វាផ្តល់នូវ high-accuracy OCR ដោយឥតគិតថ្លៃជាមួយ free tier។

### ការកំណត់រចនាសម្ព័ន្ធ

ដើម្បីកំណត់រចនាសម្ព័ន្ធ Gemini API key សូមកំណត់ environment variables នៅក្នុង server របស់អ្នក៖

```bash
# Set environment variables
export GEMINI_API_KEY="your-gemini-api-key"
export OCR_API_KEY="your-secret-api-key"
```

ឬកំណត់ក្នុងឯកសារ `.env` របស់អ្នក៖

```
GEMINI_API_KEY=your-gemini-api-key
OCR_API_KEY=your-secret-api-key
```

### របៀបបង្កើត Gemini API Key

1. ចូលទៅ [Google AI Studio](https://aistudio.google.com/)
2. ចុច "Get API Key"
3. បង្កើត new project ឬ ប្រើ existing project
4. Copy API key ហើយសរសេរវាយជាប់

### API Endpoint

**URL:** `/api/ocr-khmer.php`
**Method:** `POST`
**Content-Type:** `multipart/form-data`
**Headers:**
- `Authorization: Bearer your-secret-api-key`

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `image_file` | File | Yes | Document image file (.jpg, .png, .jpeg, .webp) - Max 10MB |

### Response

**Success Response (200 OK):**
```json
{
  "status": "success",
  "extracted_text": "អក្សរខ្មែរដែលបានស្រង់..."
}
```

**Error Response (4xx/5xx):**
```json
{
  "status": "error",
  "message": "Error description"
}
```

### ការកំណត់រចនាសម្ព័ន្ធក្នុង PHP

ក្នុងឯកសារ `ocr-khmer.php` អ្នកអាចកែប្រែការកំណត់រចនាសម្ព័ន្ធ៖

```php
$config = [
    'gemini_api_key' => getenv('GEMINI_API_KEY') ?: 'your-gemini-api-key',
    'api_auth_key' => getenv('OCR_API_KEY') ?: 'your-secret-api-key',
    'max_file_size' => 10 * 1024 * 1024, // 10MB
    'allowed_formats' => ['jpg', 'jpeg', 'png', 'webp'],
];
```

---

## ផ្នែកទី ២: Flutter Frontend Integration

### ការកែប្រែក្នុង Flutter

ខ្ញុំបានបន្ថែមនិងកែលម្អឯកសារដូចខាងក្រោម៖

#### 1. OCR Service (`lib/services/ocr_service.dart`)

បន្ថែម method ថ្មីសម្រាប់ Khmer OCR៖

```dart
Future<OCRResult> extractTextKhmer(String imagePath) async {
  // Upload image to PHP backend
  // PHP converts to Base64 and sends to Gemini 1.5 Flash
  // Return extracted Khmer text
}
```

#### 2. Document Scanner Screen (`lib/screens/document_scanner_screen.dart`)

កែលម្អ UI និង logic សម្រាប់ OCR៖

- **បន្ថែម import:** `google_fonts` សម្រាប់ Khmer font support
- **កែលម្អ `_extractText` method:** ប្រើ `extractTextKhmer()` ជំនួស ML Kit
- **កែលម្អ loading message:** "កំពុងអានអក្សរខ្មែរ..."
- **កែលម្អ UI:**
  - SafeArea wrap ដើម្បីបង្ការ status bar overlap
  - Filter labels shortened (Orig, Magic, B&W, Enh) ដើម្បីបង្ការ wrapping
  - Khmer font (Kantumruy Pro) សម្រាប់ extracted text

### UI Design Improvements

#### SafeArea Fix
- បានលុប `extendBodyBehindAppBar: true`
- បានបន្ថែម `SafeArea` widget នៅក្នុង body
- បានលុប simulated status bar overlay

#### Filter Bar Fix
- បានកែប្រែ padding: `horizontal: 8, vertical: 10`
- បានកែប្រែ font size: `fontSize: 11`
- បានកែប្រែ labels:
  - "Original" → "Orig"
  - "Magic Color" → "Magic"
  - "B&W" → "B&W" (ដដ់ស្រាប់)
  - "Enhanced" → "Enh"

#### Extracted Text Bottom Sheet
- បានបន្ថែម Khmer font: `GoogleFonts.kantumruyPro()`
- បានកែប្រែ line height: `height: 1.6`
- បានកែប្រែ loading message: "កំពុងអានអក្សរខ្មែរ..."

---

## របៀបប្រើប្រាស់

### សម្រាប់ Backend Developers

1. Upload `ocr-khmer.php` ទៅ server
2. Set environment variables (Gemini API key)
3. Test endpoint ដោយប្រើ Postman ឬ curl

**Example curl request:**
```bash
curl -X POST https://your-domain.com/api/ocr-khmer.php \
  -H "Authorization: Bearer your-secret-api-key" \
  -F "image_file=@document.jpg"
```

### សម្រាប់ Flutter Developers

1. Set OCR API key ក្នុង SharedPreferences:
   ```dart
   final prefs = await SharedPreferences.getInstance();
   await prefs.setString('ocr_api_key', 'your-secret-api-key');
   ```

2. The `extractTextKhmer()` method នឹងត្រូវបានហៅដោយស្វ័យប្រវត្តិ
   នៅពេល user ចុច "Extract Text" button

### សម្រាប់ Users

1. Open Document Scanner screen
2. Scan document using native scanner (ML Kit/VisionKit)
3. Select filter (Original, Magic Color, B&W, Enhanced)
4. Tap "Extract Text" button
5. Wait for processing ("កំពុងអានអក្សរខ្មែរ...")
6. View extracted Khmer text in bottom sheet
7. Copy text to clipboard if needed

---

## Gemini API Prompt

AI model ត្រូវបានប្រើដោយ prompt ដូចខាងក្រោម៖

```
You are an expert Khmer OCR system. Extract ALL text from this document image into accurate, beautifully formatted Khmer text. Preserve numbered lists, line breaks, headings, and paragraph structures. Return ONLY the extracted text with no extra commentary.
```

---

## Dependencies

### Backend (PHP)
- PHP 7.4+
- cURL extension
- Google Gemini API key (free tier available)

### Frontend (Flutter)
- `google_mlkit_text_recognition` - For document scanning UI (not OCR)
- `cunning_document_scanner` - For native document scanning
- `dio` - HTTP client for image upload
- `google_fonts` - For Khmer font support
- `shared_preferences` - For storing API keys

---

## Troubleshooting

### Backend Issues

**Problem:** "Unauthorized" error
**Solution:** Check that the Authorization header matches the configured `OCR_API_KEY`

**Problem:** "File size exceeds maximum limit"
**Solution:** Ensure image file is under 10MB or increase `max_file_size` in config

**Problem:** Gemini API errors
**Solution:** 
- Verify Gemini API key is valid
- Check Gemini API quota and rate limits
- Ensure image format is supported

### Frontend Issues

**Problem:** OCR fails with network error
**Solution:** Check network connection and API endpoint URL

**Problem:** Extracted text is empty
**Solution:** 
- Verify image contains readable text
- Check Gemini API response
- Try with clearer image

**Problem:** Khmer font not displaying correctly
**Solution:** 
- Ensure `google_fonts` package is properly installed
- Check that Kantumruy Pro font is available

---

## Security Notes

1. **Gemini API Key:** Never commit API keys to version control. Use environment variables.
2. **Authentication:** The endpoint uses Bearer token authentication. Ensure keys are rotated regularly.
3. **File Upload:** Validate file types and sizes on server-side to prevent abuse.
4. **Rate Limiting:** Consider implementing rate limiting to prevent API abuse.
5. **Gemini Quotas:** Be aware of Gemini API rate limits and free tier constraints.

---

## Advantages of Using Gemini 1.5 Flash for Khmer OCR

1. **High Accuracy:** Better than standard ML Kit for Khmer text
2. **Free Tier:** Available with generous free tier
3. **Format Preservation:** Maintains line breaks, lists, and headings
4. **Simple Integration:** Easy to integrate with existing PHP backend
5. **No Complex Setup:** No need for custom Khmer fonts or models

---

## Future Enhancements

- [ ] Add support for multiple image files
- [ ] Implement OCR result caching
- [ ] Add text translation feature
- [ ] Support other languages via Gemini
- [ ] Export extracted text to PDF
- [ ] Add image pre-processing for better OCR
- [ ] Support handwritten Khmer text
