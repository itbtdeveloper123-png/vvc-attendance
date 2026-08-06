# Keep Android entry points referenced by AndroidManifest.xml or Flutter MethodChannel calls.
-keep class app.vvc.MainActivity { *; }
-keep class app.vvc.MeetingRecordingService { *; }
-keep class app.vvc.MeetingPlaybackService { *; }

# MLKit Rules
-dontwarn com.google.mlkit.vision.text.**
-dontwarn com.google.mlkit.vision.common.**
-dontwarn com.google.mlkit.**
-keep class com.google.mlkit.** { *; }

