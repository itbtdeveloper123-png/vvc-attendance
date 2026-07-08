package app.vvc

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File

class MainActivity : FlutterFragmentActivity() {
    companion object {
        private const val RECORDING_CHANNEL = "app.vvc/meeting_recording"
        private const val PLAYBACK_CHANNEL = "app.vvc/meeting_playback"
        private const val APP_UPDATE_CHANNEL = "app.vvc/app_update"
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, APP_UPDATE_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "installApk" -> {
                        val path = call.argument<String>("path")
                        if (path.isNullOrBlank()) {
                            result.error("invalid_path", "APK path is required.", null)
                            return@setMethodCallHandler
                        }

                        try {
                            val apkFile = File(path)
                            if (!apkFile.exists()) {
                                result.error("file_not_found", "APK file not found: $path", null)
                                return@setMethodCallHandler
                            }

                            val apkUri = FileProvider.getUriForFile(
                                this,
                                "${applicationContext.packageName}.provider",
                                apkFile,
                            )

                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                                !packageManager.canRequestPackageInstalls()
                            ) {
                                val settingsIntent = Intent(
                                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:${applicationContext.packageName}"),
                                ).apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }

                                startActivity(settingsIntent)
                                result.error(
                                    "install_permission_required",
                                    "Allow installs from this app, then tap update again.",
                                    null,
                                )
                                return@setMethodCallHandler
                            }

                            val installIntent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                                data = apkUri
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }

                            if (installIntent.resolveActivity(packageManager) == null) {
                                result.error("no_installer", "No package installer available on this device.", null)
                                return@setMethodCallHandler
                            }

                            startActivity(installIntent)
                            result.success(true)
                        } catch (e: Exception) {
                            result.error("install_failed", e.message, null)
                        }
                    }

                    else -> result.notImplemented()
                }
            }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, RECORDING_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "startRecording" -> {
                        val path = call.argument<String>("path")
                        if (path.isNullOrBlank()) {
                            result.error("invalid_path", "Recording path is required.", null)
                            return@setMethodCallHandler
                        }
                        MeetingRecordingService.requestStart(this, path)
                        result.success(MeetingRecordingService.snapshot(this))
                    }

                    "pauseRecording" -> {
                        MeetingRecordingService.requestPause(this)
                        result.success(MeetingRecordingService.snapshot(this))
                    }

                    "resumeRecording" -> {
                        MeetingRecordingService.requestResume(this)
                        result.success(MeetingRecordingService.snapshot(this))
                    }

                    "stopRecording" -> {
                        MeetingRecordingService.requestStop(this)
                        result.success(MeetingRecordingService.snapshot(this))
                    }

                    "getState" -> {
                        result.success(MeetingRecordingService.snapshot(this))
                    }

                    "clearLastCompleted" -> {
                        MeetingRecordingService.clearLastCompleted(this)
                        result.success(true)
                    }

                    "discardLastCompleted" -> {
                        val path = call.argument<String>("path")
                        MeetingRecordingService.discardLastCompleted(this, path)
                        result.success(true)
                    }

                    else -> result.notImplemented()
                }
            }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, PLAYBACK_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "play" -> {
                        val path = call.argument<String>("path")
                        if (path.isNullOrBlank()) {
                            result.error("invalid_path", "Playback path is required.", null)
                            return@setMethodCallHandler
                        }
                        val title = call.argument<String>("title")
                        val displayPath = call.argument<String>("displayPath")
                        MeetingPlaybackService.requestPlay(
                            this,
                            source = path,
                            title = title,
                            displayPath = displayPath,
                        )
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    "pause" -> {
                        MeetingPlaybackService.requestPause(this)
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    "resume" -> {
                        MeetingPlaybackService.requestResume(this)
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    "stop" -> {
                        MeetingPlaybackService.requestStop(this)
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    "seek" -> {
                        val positionMs = call.argument<Int>("positionMs") ?: 0
                        MeetingPlaybackService.requestSeek(this, positionMs.toLong())
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    "setSpeed" -> {
                        val speed = call.argument<Double>("speed") ?: 1.0
                        MeetingPlaybackService.requestSpeed(this, speed.toFloat())
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    "getPlaybackState" -> {
                        result.success(MeetingPlaybackService.snapshot(this))
                    }

                    else -> result.notImplemented()
                }
            }
    }
}
