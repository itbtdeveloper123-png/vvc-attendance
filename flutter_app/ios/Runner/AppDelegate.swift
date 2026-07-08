import Flutter
import UIKit
import GoogleMaps

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    var mapsApiKey = (Bundle.main.object(forInfoDictionaryKey: "GoogleMapsApiKey") as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if mapsApiKey.isEmpty || mapsApiKey.hasPrefix("$") {
      NSLog("GoogleMapsApiKey is not configured. Using fallback dummy key to prevent crash.")
      mapsApiKey = "AIzaSyDummyKey-PleaseConfigureYourOwnInMapsApiKeyXCConfig"
    }
    GMSServices.provideAPIKey(mapsApiKey)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
  }
}
