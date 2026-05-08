package app.vvc

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.media.MediaRecorder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.util.Locale

class MeetingRecordingService : Service() {
    companion object {
        private const val CHANNEL_ID = "meeting_recording_controls_channel"
        private const val CHANNEL_NAME = "Meeting Recording Controls"
        private const val NOTIFICATION_ID = 901

        private const val ACTION_START = "app.vvc.action.START_MEETING_RECORDING"
        private const val ACTION_PAUSE = "app.vvc.action.PAUSE_MEETING_RECORDING"
        private const val ACTION_RESUME = "app.vvc.action.RESUME_MEETING_RECORDING"
        private const val ACTION_STOP = "app.vvc.action.STOP_MEETING_RECORDING"
        private const val EXTRA_PATH = "extra_path"

        private const val PREFS_NAME = "FlutterSharedPreferences"
        private const val PREF_ACTIVE = "flutter.meeting_recording_active"
        private const val PREF_PAUSED = "flutter.meeting_recording_paused"
        private const val PREF_PATH = "flutter.meeting_recording_path"
        private const val PREF_ELAPSED = "flutter.meeting_recording_elapsed_ms"
        private const val PREF_LAST_PATH = "flutter.meeting_recording_last_path"
        private const val PREF_LAST_DURATION = "flutter.meeting_recording_last_duration_ms"

        @Volatile
        private var activeService: MeetingRecordingService? = null

        fun requestStart(context: Context, path: String) {
            activeService?.startRecordingInternal(path) ?: ContextCompat.startForegroundService(
                context,
                Intent(context, MeetingRecordingService::class.java).apply {
                    action = ACTION_START
                    putExtra(EXTRA_PATH, path)
                },
            )
        }

        fun requestPause(context: Context) {
            activeService?.pauseRecordingInternal() ?: context.startService(
                Intent(context, MeetingRecordingService::class.java).apply {
                    action = ACTION_PAUSE
                },
            )
        }

        fun requestResume(context: Context) {
            activeService?.resumeRecordingInternal() ?: context.startService(
                Intent(context, MeetingRecordingService::class.java).apply {
                    action = ACTION_RESUME
                },
            )
        }

        fun requestStop(context: Context) {
            activeService?.stopRecordingInternal() ?: context.startService(
                Intent(context, MeetingRecordingService::class.java).apply {
                    action = ACTION_STOP
                },
            )
        }

        fun snapshot(context: Context): HashMap<String, Any?> {
            val prefs = context.getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            return hashMapOf(
                "active" to prefs.getBoolean(PREF_ACTIVE, false),
                "isRecording" to (prefs.getBoolean(PREF_ACTIVE, false) && !prefs.getBoolean(PREF_PAUSED, false)),
                "isPaused" to prefs.getBoolean(PREF_PAUSED, false),
                "activePath" to prefs.getString(PREF_PATH, null),
                "elapsedMs" to prefs.getLong(PREF_ELAPSED, 0L),
                "lastCompletedPath" to prefs.getString(PREF_LAST_PATH, null),
                "lastCompletedDurationMs" to prefs.getLong(PREF_LAST_DURATION, 0L),
            )
        }

        fun clearLastCompleted(context: Context) {
            context.getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                .edit()
                .remove(PREF_LAST_PATH)
                .remove(PREF_LAST_DURATION)
                .apply()
        }

        fun discardLastCompleted(context: Context, explicitPath: String?) {
            val prefs = context.getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            val storedPath = prefs.getString(PREF_LAST_PATH, null)
            val targetPath = explicitPath?.takeIf { it.isNotBlank() } ?: storedPath
            if (!targetPath.isNullOrBlank()) {
                runCatching { File(targetPath).delete() }
            }
            clearLastCompleted(context)
        }
    }

    private var recorder: MediaRecorder? = null
    private var currentPath: String? = null
    private var isPaused: Boolean = false
    private var accumulatedElapsedMs: Long = 0L
    private var segmentStartedElapsedMs: Long = 0L
    private var lastCompletedPath: String? = null
    private var lastCompletedDurationMs: Long = 0L

    private val handler = Handler(Looper.getMainLooper())
    private val notificationTicker = object : Runnable {
        override fun run() {
            if (!isSessionActive()) {
                return
            }
            persistState()
            updateNotification()
            handler.postDelayed(this, 1000L)
        }
    }

    override fun onCreate() {
        super.onCreate()
        activeService = this
        createNotificationChannel()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        releaseRecorder()
        if (activeService === this) {
            activeService = null
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val path = intent.getStringExtra(EXTRA_PATH)
                if (!path.isNullOrBlank()) {
                    startRecordingInternal(path)
                }
            }

            ACTION_PAUSE -> pauseRecordingInternal()
            ACTION_RESUME -> resumeRecordingInternal()
            ACTION_STOP -> stopRecordingInternal()
            else -> {
                if (isSessionActive()) {
                    updateNotification()
                }
            }
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Foreground meeting audio recording controls."
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        manager.createNotificationChannel(channel)
    }

    private fun startRecordingInternal(path: String) {
        if (isSessionActive()) {
            return
        }

        runCatching {
            File(path).parentFile?.mkdirs()
        }

        lastCompletedPath = null
        lastCompletedDurationMs = 0L
        currentPath = path
        isPaused = false
        accumulatedElapsedMs = 0L
        segmentStartedElapsedMs = SystemClock.elapsedRealtime()
        persistState()

        startForegroundSafely(buildNotification())

        try {
            recorder = createRecorder(path).apply {
                prepare()
                start()
            }
            startTicker()
            updateNotification()
        } catch (error: Exception) {
            releaseRecorder()
            clearActiveSessionState()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun pauseRecordingInternal() {
        if (!isSessionActive() || isPaused) {
            return
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return
        }

        try {
            recorder?.pause()
            accumulatedElapsedMs = totalElapsedMs()
            segmentStartedElapsedMs = 0L
            isPaused = true
            persistState()
            updateNotification()
        } catch (_: Exception) {
        }
    }

    private fun resumeRecordingInternal() {
        if (!isSessionActive() || !isPaused) {
            return
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return
        }

        try {
            recorder?.resume()
            isPaused = false
            segmentStartedElapsedMs = SystemClock.elapsedRealtime()
            persistState()
            updateNotification()
            startTicker()
        } catch (_: Exception) {
        }
    }

    private fun stopRecordingInternal() {
        if (!isSessionActive()) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        handler.removeCallbacks(notificationTicker)

        val finalPath = currentPath
        val finalDurationMs = totalElapsedMs()
        var isValidRecording = false

        try {
            recorder?.stop()
            isValidRecording = !finalPath.isNullOrBlank() && File(finalPath).exists() && File(finalPath).length() > 0L
        } catch (_: Exception) {
            if (!finalPath.isNullOrBlank()) {
                runCatching { File(finalPath).delete() }
            }
        } finally {
            releaseRecorder()
        }

        if (isValidRecording && !finalPath.isNullOrBlank()) {
            lastCompletedPath = finalPath
            lastCompletedDurationMs = finalDurationMs
        } else {
            lastCompletedPath = null
            lastCompletedDurationMs = 0L
        }

        clearActiveSessionState()
        persistState()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun clearActiveSessionState() {
        currentPath = null
        isPaused = false
        accumulatedElapsedMs = 0L
        segmentStartedElapsedMs = 0L
    }

    private fun releaseRecorder() {
        recorder?.runCatching { reset() }
        recorder?.runCatching { release() }
        recorder = null
    }

    private fun createRecorder(path: String): MediaRecorder {
        val instance = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            MediaRecorder(this)
        } else {
            @Suppress("DEPRECATION")
            MediaRecorder()
        }

        return instance.apply {
            setAudioSource(MediaRecorder.AudioSource.MIC)
            setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            setAudioChannels(1)
            setAudioEncodingBitRate(48000)
            setAudioSamplingRate(32000)
            setOutputFile(path)
        }
    }

    private fun isSessionActive(): Boolean = recorder != null && !currentPath.isNullOrBlank()

    private fun totalElapsedMs(): Long {
        val base = accumulatedElapsedMs
        return if (isSessionActive() && !isPaused && segmentStartedElapsedMs > 0L) {
            base + (SystemClock.elapsedRealtime() - segmentStartedElapsedMs)
        } else {
            base
        }
    }

    private fun startTicker() {
        handler.removeCallbacks(notificationTicker)
        handler.post(notificationTicker)
    }

    private fun updateNotification() {
        val manager = ContextCompat.getSystemService(this, NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification())
    }

    private fun buildNotification(): Notification {
        val elapsedMs = totalElapsedMs()
        val paused = isPaused
        val title = if (paused) "ការថតសំឡេងបានផ្អាក" else "កំពុងថតសំឡេងប្រជុំ"
        val content = if (paused) {
            "បានថតរួច ${formatDuration(elapsedMs)} • ចុចបន្ត ឬឈប់"
        } else {
            "កំពុងថត ${formatDuration(elapsedMs)}"
        }

        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                2001,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }

        val pauseResumeIntent = Intent(this, MeetingRecordingService::class.java).apply {
            action = if (paused) ACTION_RESUME else ACTION_PAUSE
        }
        val stopIntent = Intent(this, MeetingRecordingService::class.java).apply {
            action = ACTION_STOP
        }

        val pauseResumePendingIntent = PendingIntent.getService(
            this,
            2002,
            pauseResumeIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopPendingIntent = PendingIntent.getService(
            this,
            2003,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_btn_speak_now)
            .setContentTitle(title)
            .setContentText(content)
            .setSubText("VVC Meetings")
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(
                NotificationCompat.Action(
                    if (paused) android.R.drawable.ic_media_play else android.R.drawable.ic_media_pause,
                    if (paused) "បន្ត" else "ផ្អាក",
                    pauseResumePendingIntent,
                ),
            )
            .addAction(
                NotificationCompat.Action(
                    android.R.drawable.ic_menu_close_clear_cancel,
                    "ឈប់",
                    stopPendingIntent,
                ),
            )

        if (contentIntent != null) {
            builder.setContentIntent(contentIntent)
        }

        if (!paused) {
            builder
                .setUsesChronometer(true)
                .setWhen(System.currentTimeMillis() - elapsedMs)
                .setShowWhen(true)
        } else {
            builder
                .setUsesChronometer(false)
                .setShowWhen(false)
        }

        return builder.build()
    }

    private fun persistState() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        prefs.edit().apply {
            putBoolean(PREF_ACTIVE, isSessionActive())
            putBoolean(PREF_PAUSED, isPaused)
            if (currentPath.isNullOrBlank()) {
                remove(PREF_PATH)
            } else {
                putString(PREF_PATH, currentPath)
            }
            putLong(PREF_ELAPSED, totalElapsedMs())
            if (lastCompletedPath.isNullOrBlank()) {
                remove(PREF_LAST_PATH)
                remove(PREF_LAST_DURATION)
            } else {
                putString(PREF_LAST_PATH, lastCompletedPath)
                putLong(PREF_LAST_DURATION, lastCompletedDurationMs)
            }
        }.apply()
    }

    private fun startForegroundSafely(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfoCompat.microphoneForegroundType(),
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun formatDuration(durationMs: Long): String {
        val totalSeconds = (durationMs / 1000L).coerceAtLeast(0L)
        val hours = totalSeconds / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        return if (hours > 0) {
            String.format(Locale.getDefault(), "%02d:%02d:%02d", hours, minutes, seconds)
        } else {
            String.format(Locale.getDefault(), "%02d:%02d", minutes, seconds)
        }
    }
}

private object ServiceInfoCompat {
    fun microphoneForegroundType(): Int {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
        } else {
            0
        }
    }
}
