# VVC Attendance

## Local Configuration

Google Maps keys are intentionally kept out of source files. Configure them per
machine or per CI environment:

- Android: add `GOOGLE_MAPS_API_KEY=your_key_here` to `android/local.properties`,
  or pass `-PGOOGLE_MAPS_API_KEY=your_key_here` to Gradle.
- iOS: copy `ios/Flutter/MapsApiKey.example.xcconfig` to
  `ios/Flutter/MapsApiKey.xcconfig`, then set `GOOGLE_MAPS_API_KEY`.
- Web: copy `web/config.example.js` to `web/config.js`, then set
  `googleMapsApiKey`.

Restrict the key in Google Cloud Console by package name/SHA-1 for Android,
bundle ID for iOS, and allowed domains for Web.
