# Khmer Meeting Summarizer Feature (GitHub Models Integration)

លក្ខណសម្ព័ន្ធថ្មីសម្រាប់ការសង្ខេបកិច្ចប្រជុំជាភាសាខ្មែរដោយប្រើ GitHub Models API

## ផ្នែកទី ១: PHP Backend API

### ឯកសារ៖ `api/process-meeting.php`

នេះគឺជា PHP REST API endpoint ដែលដំណើរការសំឡេងកិច្ចប្រជុំដោយប្រើ **GitHub Models API**៖
1. **OpenAI Whisper via GitHub Models** - សម្រាប់បម្លែងសំឡេងទៅជាអត្ថបទភាសាខ្មែរ (Speech-to-Text)
2. **OpenAI GPT-4o via GitHub Models** - សម្រាប់សង្ខេបកិច្ចប្រជុំជាភាសាខ្មែរ

### អ្វីទៅ GitHub Models API?

GitHub Models API ផ្តល់នូវ access ទៅសេវីស AI models ពី OpenAI, Meta, Mistral, និងផ្សេងទៀតតាមរយៈ GitHub platform។ វាអាចប្រើបានដោយ GitHub Personal Access Token (PAT)។

### ការកំណត់រចនាសម្ព័ន្ធ

ដើម្បីកំណត់រចនាសម្ព័ន្ធ GitHub PAT សូមកំណត់ environment variables នៅក្នុង server របស់អ្នក៖

```bash
# Set environment variables
export GITHUB_PAT="your-github-personal-access-token"
export MEETING_API_KEY="your-secret-api-key"
```

ឬកំណត់ក្នុងឯកសារ `.env` របស់អ្នក៖

```
GITHUB_PAT=your-github-personal-access-token
MEETING_API_KEY=your-secret-api-key
```

### របៀបបង្កើត GitHub Personal Access Token (PAT)

1. ចូលទៅ GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. ចុច "Generate new token (classic)"
3. ដាក់ឈ្មោះ token (ឧ: "Meeting Summarizer")
4. ជ្រើស scopes:
   - `read:org` (សម្រាប់ access GitHub Models)
   - `read:user` (សម្រាប់ user data)
5. ចុច "Generate token"
6. Copy token ហើយសរសេរវាយជាប់

### API Endpoint

**URL:** `/api/process-meeting.php`
**Method:** `POST`
**Content-Type:** `multipart/form-data`
**Headers:**
- `Authorization: Bearer your-secret-api-key`

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `audio_file` | File | Yes | Audio file (.m4a, .mp3, .wav, .ogg, .flac) - Max 25MB |
| `meeting_id` | String | No | Meeting ID (optional) |
| `meeting_title` | String | No | Meeting title (optional) |
| `department` | String | No | Department name (optional) |

### Response

**Success Response (200 OK):**
```json
{
  "status": "success",
  "transcript": "ខ្លឹមសារសំឡេងដែលបានបម្លែង...",
  "summary": "💡 ចំណុចសំខាន់ៗនៃកិច្ចប្រជុំ...\n🎯 កិច្ចការដែលត្រូវធ្វើបន្ត...",
  "meeting_title": "test",
  "date": "30/04/2026",
  "department": "CKD",
  "meeting_id": "123"
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

ក្នុងឯកសារ `process-meeting.php` អ្នកអាចកែប្រែការកំណត់រចនាសម្ព័ន្ធ៖

```php
$config = [
    'github_pat' => getenv('GITHUB_PAT') ?: 'your-github-pat',
    'api_auth_key' => getenv('MEETING_API_KEY') ?: 'your-secret-api-key',
    'max_file_size' => 25 * 1024 * 1024, // 25MB
    'allowed_formats' => ['m4a', 'mp3', 'wav', 'ogg', 'flac'],
    'github_models_endpoint' => 'https://models.inference.ai.azure.com',
];
```

---

## ផ្នែកទី ២: Flutter Frontend Integration

### ការកែប្រែក្នុង Flutter

ខ្ញុំបានបន្ថែមនិងកែលម្អឯកសារដូចខាងក្រោម៖

#### 1. API Service (`lib/services/api_service.dart`)

បន្ថែម method សម្រាប់ការដំណើរការសំឡេងកិច្ចប្រជុំ៖

```dart
Future<Map<String, dynamic>> processMeetingAudio({
  required String audioPath,
  String? meetingId,
  String? meetingTitle,
  String? department,
}) async {
  // Implementation uses Dio for multipart file upload
  // Calls /process-meeting.php endpoint (now using GitHub Models API)
}
```

#### 2. Meetings Screen (`lib/screens/meetings_screen.dart`)

កែលម្អ UI និង logic សម្រាប់ AI summary៖

- **បន្ថែម import:** `package:http/http.dart` សម្រាប់ download audio file
- **កែលម្អ `_generateAISummary` method:** ប្រើ PHP endpoint ថ្មីជាមុម្ម old method
- **កែលម្អ UI:** បន្ថែម "សង្ខេបម្ដងទៀត" button និងប្តូរ loading message
- **បន្ថែម `_downloadAudioFile` method:** Download audio ពី server មុនពេលផ្ញើទៅ API

### UI Design (ដូច wireframe)

#### Meeting Info Card
- Icon: Mic icon (orange)
- Meeting Name (bold)
- Date (secondary color)
- Department with folder icon

#### AI Summary Card
- Title: "សេចក្តីសង្ខេបដោយ AI" ជាមួយ sparkle icon
- Copy button (ចម្លងអត្ថបទ)
- Resummarize button (សង្ខេបម្ដងទៀត) ជាមួយ refresh icon
- Loading state: "កំពុងដំណើរការសង្ខេបដោយ AI..."
- Error state: បង្ហាញ error message ជាមួយ retry option
- Success state: បង្ហាញ summary text

#### Related Photos Section
- Title: "រូបភាពពាក់ព័ន្ធ (count)"
- Horizontal scroll នៃ thumbnails

#### Bottom Action Button
- Green button: "សកម្មភាព / ស្តាប់សំឡេងកិច្ចប្រជុំ"
- Play audio ដោយប្រើ audioplayers package

---

## របៀបប្រើប្រាស់

### សម្រាប់ Backend Developers

1. Upload `process-meeting.php` ទៅ server
2. Set environment variables (GitHub PAT)
3. Test endpoint ដោយប្រើ Postman ឬ curl

**Example curl request:**
```bash
curl -X POST https://your-domain.com/api/process-meeting.php \
  -H "Authorization: Bearer your-secret-api-key" \
  -F "audio_file=@meeting.m4a" \
  -F "meeting_title=Weekly Meeting" \
  -F "department=CKD"
```

### សម្រាប់ Flutter Developers

1. Set API key ក្នុង SharedPreferences (នៅក្នុង `_getMeetingApiKey` method)
2. Call `_generateAISummary` method ពី meeting detail modal
3. UI នឹងបង្ហាញ loading state ខណៈពេល processing
4. Summary នឹងបង្ហាញក្នុង AI Summary Card

### សម្រាប់ Users

1. Open Meetings screen
2. Tap on a meeting to view details
3. In the detail modal, tap "ចុចដើម្បីសង្ខេបដោយ AI" ឬ click the refresh icon
4. Wait for processing (audio transcription via GitHub Models + AI summarization)
5. View the Khmer summary with key highlights and action items
6. Copy summary to clipboard if needed
7. Tap "សង្ខេបម្ដងទៀត" to regenerate if needed

---

## សេចក្តីសង្ខេប Khmer Prompt

AI model ត្រូវបានប្រើដោយ prompt ដូចខាងក្រោម៖

```
សូមសង្ខេបខ្លឹមសារនៃកិច្ចប្រជុំខាងក្រោមនេះជាភាសាខ្មែរឱ្យបានច្បាស់លាស់ ខ្លីខ្លឹម និងមានរបៀបរៀបរយ៖

កិច្ចប្រជុំ៖ [meeting_title]
ផ្នែក៖ [department]

ខ្លឹមសារកិច្ចប្រជុំ៖
[transcript]

សូមរាយការណ៍សេចក្តីសង្ខេបតាមរបៀបដូចខាងក្រោម៖
- 💡 ចំណុចសំខាន់ៗនៃកិច្ចប្រជុំ (Key Highlights)
- 🎯 កិច្ចការដែលត្រូវធ្វើបន្ត (Action Items)
- 👤 អ្នកទទួលខុសត្រូវ (Assignees/Roles, if mentioned)
```

---

## Dependencies

### Backend (PHP)
- PHP 7.4+
- cURL extension
- GitHub Personal Access Token (PAT) with Models access

### Frontend (Flutter)
- `dio` - HTTP client for file upload
- `http` - For downloading audio files
- `audioplayers` - For playing meeting audio
- `flutter/services` - For clipboard operations

---

## Troubleshooting

### Backend Issues

**Problem:** "Unauthorized" error
**Solution:** Check that the Authorization header matches the configured `MEETING_API_KEY`

**Problem:** "File size exceeds maximum limit"
**Solution:** Ensure audio file is under 25MB or increase `max_file_size` in config

**Problem:** GitHub Models API errors
**Solution:** 
- Verify GitHub PAT is valid
- Ensure PAT has correct scopes (`read:org`, `read:user`)
- Check GitHub Models availability for your organization

### Frontend Issues

**Problem:** Audio download fails
**Solution:** Check that `audio_path` is valid and server is accessible

**Problem:** Summary not updating
**Solution:** Check network connection and API endpoint URL

---

## Security Notes

1. **GitHub PAT:** Never commit GitHub PAT to version control. Use environment variables.
2. **Authentication:** The endpoint uses Bearer token authentication. Ensure keys are rotated regularly.
3. **File Upload:** Validate file types and sizes on server-side to prevent abuse.
4. **Rate Limiting:** Consider implementing rate limiting to prevent API abuse.
5. **GitHub Models Quotas:** Be aware of GitHub Models API rate limits and quotas.

---

## Advantages of Using GitHub Models API

1. **Single Platform:** Access multiple AI models (OpenAI, Meta, Mistral) via one API
2. **GitHub Integration:** Easy to use if you already use GitHub for development
3. **Unified Billing:** Pay through GitHub account
4. **No Direct OpenAI Key:** Avoid managing separate OpenAI API keys
5. **Simplified Setup:** Only need GitHub PAT instead of multiple API keys

---

## Future Enhancements

- [ ] Add support for multiple audio files
- [ ] Implement caching for transcripts
- [ ] Add speaker identification
- [ ] Support real-time transcription
- [ ] Add meeting analytics dashboard
- [ ] Export summary to PDF
- [ ] Email summary to participants
- [ ] Support other models via GitHub Models (Meta Llama, Mistral, etc.)
