import 'dart:js_interop';

@JS('presentPwaInstallPrompt')
external void _presentPwaInstallPrompt();

void presentPwaInstallPrompt() {
  _presentPwaInstallPrompt();
}
