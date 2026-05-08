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
flutter build ios --release --no-codesign

if [[ ! -d "$APP_BUNDLE" ]]; then
  echo "Expected app bundle was not found at: $APP_BUNDLE"
  exit 1
fi

echo "Packaging IPA for AltStore..."
rm -rf "$PAYLOAD_DIR" "$IPA_PATH"
mkdir -p "$PAYLOAD_DIR"
cp -R "$APP_BUNDLE" "$PAYLOAD_DIR/"

(
  cd "$IPA_DIR"
  /usr/bin/zip -qry "$IPA_NAME" Payload
)

echo "Built: $IPA_PATH"
