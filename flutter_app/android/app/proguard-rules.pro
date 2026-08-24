# Keep Android entry points referenced by AndroidManifest.xml or Flutter MethodChannel calls.
-keep class app.vvc.MainActivity { *; }
-keep class app.vvc.MeetingRecordingService { *; }
-keep class app.vvc.MeetingPlaybackService { *; }

# MLKit & TensorFlow Lite Rules
-dontwarn com.google.mlkit.vision.text.**
-dontwarn com.google.mlkit.vision.common.**
-dontwarn com.google.mlkit.**
-keep class com.google.mlkit.** { *; }
-dontwarn org.tensorflow.lite.**
-dontwarn org.tensorflow.lite.gpu.**
-keep class org.tensorflow.lite.** { *; }

# Agora RTC SDK Rules
-dontwarn io.agora.**
-keep class io.agora.** { *; }

