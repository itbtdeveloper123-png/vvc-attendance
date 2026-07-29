# iOS Google Maps API Key Setup

## Problem
If the app crashes when entering the Google Maps page on iOS builds (IPA), it's likely due to missing or misconfigured Google Maps API key.

## Solution

### Step 1: Create MapsApiKey.xcconfig
Copy the example file to create your own API key configuration:

```bash
cp ios/Flutter/MapsApiKey.example.xcconfig ios/Flutter/MapsApiKey.xcconfig
```

### Step 2: Add Your Google Maps API Key
Edit `ios/Flutter/MapsApiKey.xcconfig` and replace the API key with your own:

```
GOOGLE_MAPS_API_KEY=YOUR_GOOGLE_MAPS_API_KEY_HERE
```

### Step 3: Get a Google Maps API Key
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable "Maps SDK for iOS" 
4. Create API key with restrictions:
   - Application restrictions: iOS bundle ID (app.vvc)
   - API restrictions: Maps SDK for iOS
5. Copy the API key and paste it in MapsApiKey.xcconfig

### Step 4: Build Configuration
The API key is automatically included in both Debug and Release builds through:
- `ios/Flutter/Debug.xcconfig` (includes MapsApiKey.xcconfig)
- `ios/Flutter/Release.xcconfig` (includes MapsApiKey.xcconfig)
- `ios/Runner/Info.plist` (uses $(GOOGLE_MAPS_API_KEY) variable)

### Important Notes
- `MapsApiKey.xcconfig` is gitignored for security reasons
- Each developer needs to create their own local copy
- For production builds, use a restricted API key
- Never commit actual API keys to the repository

### Troubleshooting
If the app still crashes:
1. Verify the API key is valid and has Maps SDK for iOS enabled
2. Check that bundle ID restrictions match your app's bundle ID
3. Ensure the MapsApiKey.xcconfig file exists and is properly formatted
4. Clean build folder: `flutter clean && flutter pub get`
5. Reinstall pods: `cd ios && pod install && cd ..`
