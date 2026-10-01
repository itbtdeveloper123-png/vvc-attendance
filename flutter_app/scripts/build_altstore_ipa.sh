#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "iOS IPA builds require macOS with Xcode installed."
  echo "Run this script on a Mac, then install the IPA with AltStore."
  exit 1
fi

if ! command -v flutter >/dev/null 2>&1; then
  echo "Flutter is not in PATH. Add flutter/bin to PATH and run again."
  exit 1
fi

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "Xcode command line tools are missing. Install Xcode, then run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
  exit 1
fi

if ! command -v pod >/dev/null 2>&1; then
  echo "CocoaPods is missing. Install it on the Mac first, for example: sudo gem install cocoapods"
  exit 1
fi

APP_BUNDLE="build/ios/iphoneos/Runner.app"
IPA_DIR="build/ios/ipa"
PAYLOAD_DIR="$IPA_DIR/Payload"
IPA_NAME="${IPA_NAME:-Vvc-HRM-AltStore.ipa}"
IPA_PATH="$IPA_DIR/$IPA_NAME"

echo "Getting Flutter packages..."
flutter pub get

echo "Building unsigned iOS app bundle..."
export FLUTTER_NO_CODESIGN=true
flutter build ios --release --no-codesign 2>&1 || {
  echo "iOS build failed. Attempting pod install and retry..."
  cd ios && pod install --repo-update && cd ..
  flutter build ios --release --no-codesign
}

if [[ ! -d "$APP_BUNDLE" ]]; then
  echo "Expected app bundle was not found at: $APP_BUNDLE"
  exit 1
fi

echo "Sanitizing frameworks for Sideloadly / AltStore signing..."
if [ -d "$APP_BUNDLE/Frameworks" ]; then
  find "$APP_BUNDLE/Frameworks" -type f | while read -r file; do
    if file "$file" | grep -q "Mach-O"; then
      archs=$(lipo -archs "$file" 2>/dev/null || echo "")
      if echo "$archs" | grep -q "arm64"; then
        lipo -thin arm64 "$file" -output "$file.thin" 2>/dev/null && mv "$file.thin" "$file" || true
      fi
      xcrun bitcode_strip -r "$file" -o "$file" 2>/dev/null || true
      strip -x "$file" 2>/dev/null || true
      codesign --force --sign - "$file" 2>/dev/null || true
    fi
  done
fi

echo "Packaging IPA for AltStore / Sideloadly..."
rm -rf "$PAYLOAD_DIR" "$IPA_PATH"
mkdir -p "$PAYLOAD_DIR"
cp -R "$APP_BUNDLE" "$PAYLOAD_DIR/"

(
  cd "$IPA_DIR"
  rm -f "$IPA_NAME"
  /usr/bin/zip -qry "$IPA_NAME" Payload -x "*/Info.plist"
  /usr/bin/zip -qry -0 "$IPA_NAME" Payload -i "*/Info.plist"
)

echo "Built: $IPA_PATH"
