# VVC HRM Store Release Checklist

Use this checklist before uploading a new Android or iOS build.

## Visual Polish

- Verify app icon, adaptive icon, and splash screen on light/dark device themes.
- Capture screenshots from real screens: login, home dashboard, attendance, request form, profile, and notifications.
- Check Khmer text on small phones so labels, buttons, and cards do not overflow.
- Confirm loading, empty, error, and no-permission states look complete.

## Permissions

- Android: confirm location, camera, notification, file/install, and exact alarm permissions are only used where needed.
- iOS: confirm `Info.plist` permission descriptions are clear and human-readable.
- Test first-run permission prompts on a clean install.

## API And Keys

- Restrict Google Maps API keys by app package/bundle ID and SHA-1 where possible.
- Keep local-only key files out of Git: Android `local.properties`, iOS `MapsApiKey.xcconfig`, and web `config.js`.
- Confirm production API URL points to the live server.
- Upload the matching `api.php` and admin PHP files before releasing the app.

## Account And Role Testing

- Test at least one account per role: Employee, Worker, Skills, HRM, Admin, Accounting.
- Verify hidden Worker cards stay hidden after logout/login and app reinstall.
- Confirm request forms submit, update, and show validation errors correctly.
- Confirm notifications arrive on Android and iOS devices.

## Build

- Android debug smoke test:
  `flutter build apk --debug`
- Android release:
  `flutter build appbundle --release`
- iOS release from macOS:
  `flutter build ipa --release`
- Increment version/build number in `pubspec.yaml` before submitting.

## Store Submission

- Prepare privacy policy URL.
- Fill data safety / privacy nutrition labels based on actual data collected.
- Use screenshots from the current build only.
- Keep release notes short and user-facing.
