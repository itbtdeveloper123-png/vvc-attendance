package app.vvc

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.MediaMetadata
import android.media.MediaPlayer
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import android.support.v4.media.MediaMetadataCompat
import android.support.v4.media.session.MediaSessionCompat
import android.support.v4.media.session.PlaybackStateCompat
import java.util.Locale

class MeetingPlaybackService : Service() {
    companion object {
        private const val CHANNEL_ID = "meeting_playback_controls_channel"
        private const val CHANNEL_NAME = "Meeting Playback Controls"
        private const val NOTIFICATION_ID = 902

        private const val ACTION_PLAY = "app.vvc.action.PLAY_MEETING_AUDIO"
        private const val ACTION_PAUSE = "app.vvc.action.PAUSE_MEETING_AUDIO"
        private const val ACTION_RESUME = "app.vvc.action.RESUME_MEETING_AUDIO"
        private const val ACTION_STOP = "app.vvc.action.STOP_MEETING_AUDIO"
        private const val ACTION_SEEK = "app.vvc.action.SEEK_MEETING_AUDIO"
        private const val ACTION_SPEED = "app.vvc.action.SPEED_MEETING_AUDIO"

        private const val EXTRA_SOURCE = "extra_source"
        private const val EXTRA_TITLE = "extra_title"
        private const val EXTRA_DISPLAY_PATH = "extra_display_path"
        private const val EXTRA_POSITION_MS = "extra_position_ms"
        private const val EXTRA_SPEED = "extra_speed"

        private const val PREFS_NAME = "FlutterSharedPreferences"
        private const val PREF_ACTIVE = "flutter.meeting_playback_active"
        private const val PREF_PLAYING = "flutter.meeting_playback_playing"
        private const val PREF_LOADING = "flutter.meeting_playback_loading"
        private const val PREF_PATH = "flutter.meeting_playback_path"
        private const val PREF_TITLE = "flutter.meeting_playback_title"
        private const val PREF_DURATION = "flutter.meeting_playback_duration_ms"
        private const val PREF_POSITION = "flutter.meeting_playback_position_ms"
        private const val PREF_SPEED = "flutter.meeting_playback_speed"

        @Volatile
        private var activeService: MeetingPlaybackService? = null

        fun requestPlay(
            context: Context,
            source: String,
            title: String?,
            displayPath: String?,
        ) {
            activeService?.playInternal(source, title, displayPath) ?: ContextCompat.startForegroundService(
                context,
                Intent(context, MeetingPlaybackService::class.java).apply {
                    action = ACTION_PLAY
                    putExtra(EXTRA_SOURCE, source)
                    putExtra(EXTRA_TITLE, title)
                    putExtra(EXTRA_DISPLAY_PATH, displayPath)
                },
            )
        }

        fun requestPause(context: Context) {
            activeService?.pauseInternal() ?: context.startService(
                Intent(context, MeetingPlaybackService::class.java).apply {
                    action = ACTION_PAUSE
                },
            )
        }

        fun requestResume(context: Context) {
            activeService?.resumeInternal() ?: context.startService(
                Intent(context, MeetingPlaybackService::class.java).apply {
                    action = ACTION_RESUME
                },
            )
        }

        fun requestStop(context: Context) {
            activeService?.stopInternal() ?: context.startService(
                Intent(context, MeetingPlaybackService::class.java).apply {
                    action = ACTION_STOP
                },
            )
        }

        fun requestSeek(context: Context, positionMs: Long) {
            activeService?.seekInternal(positionMs) ?: context.startService(
                Intent(context, MeetingPlaybackService::class.java).apply {
                    action = ACTION_SEEK
                    putExtra(EXTRA_POSITION_MS, positionMs)
                },
            )
        }

        fun requestSpeed(context: Context, speed: Float) {
            activeService?.setSpeedInternal(speed) ?: context.startService(
                Intent(context, MeetingPlaybackService::class.java).apply {
                    action = ACTION_SPEED
                    putExtra(EXTRA_SPEED, speed)
                },
            )
        }

        fun snapshot(context: Context): HashMap<String, Any?> {
            val prefs = context.getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            return hashMapOf(
                "active" to prefs.getBoolean(PREF_ACTIVE, false),
                "isPlaying" to prefs.getBoolean(PREF_PLAYING, false),
                "isLoading" to prefs.getBoolean(PREF_LOADING, false),
                "currentPath" to prefs.getString(PREF_PATH, null),
                "currentTitle" to prefs.getString(PREF_TITLE, null),
                "durationMs" to prefs.getLong(PREF_DURATION, 0L),
                "positionMs" to prefs.getLong(PREF_POSITION, 0L),
                "playbackSpeed" to prefs.getFloat(PREF_SPEED, 1.0f).toDouble(),
            )
        }
    }

    private var mediaPlayer: MediaPlayer? = null
    private lateinit var mediaSession: MediaSessionCompat
    private var currentSource: String? = null
    private var currentDisplayPath: String? = null
    private var currentTitle: String? = null
    private var playbackSpeed: Float = 1.0f
    private var isPreparing: Boolean = false

    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            if (!isSessionActive()) {
                return
            }
            persistState()
            updatePlaybackState()
            updateNotification()
            handler.postDelayed(this, 1000L)
        }
    }

    override fun onCreate() {
        super.onCreate()
        activeService = this
        createNotificationChannel()
        mediaSession = MediaSessionCompat(this, "MeetingPlaybackSession").apply {
            setFlags(
                MediaSessionCompat.FLAG_HANDLES_MEDIA_BUTTONS or
                    MediaSessionCompat.FLAG_HANDLES_TRANSPORT_CONTROLS,
            )
            setCallback(
                object : MediaSessionCompat.Callback() {
                    override fun onPlay() {
                        resumeInternal()
                    }

                    override fun onPause() {
                        pauseInternal()
                    }

                    override fun onStop() {
                        stopInternal()
                    }

                    override fun onSeekTo(pos: Long) {
                        seekInternal(pos)
                    }
                },
            )
            isActive = true
        }
        persistState()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        releasePlayer()
        if (::mediaSession.isInitialized) {
            mediaSession.isActive = false
            mediaSession.release()
        }
        if (activeService === this) {
            activeService = null
        }
        clearSessionState()
        persistState()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_PLAY -> {
                val source = intent.getStringExtra(EXTRA_SOURCE)
                if (!source.isNullOrBlank()) {
                    playInternal(
                        source = source,
                        title = intent.getStringExtra(EXTRA_TITLE),
                        displayPath = intent.getStringExtra(EXTRA_DISPLAY_PATH),
                    )
                }
            }

            ACTION_PAUSE -> pauseInternal()
            ACTION_RESUME -> resumeInternal()
            ACTION_STOP -> stopInternal()
            ACTION_SEEK -> seekInternal(intent.getLongExtra(EXTRA_POSITION_MS, 0L))
            ACTION_SPEED -> setSpeedInternal(intent.getFloatExtra(EXTRA_SPEED, 1.0f))
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
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Foreground meeting audio playback controls."
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        manager.createNotificationChannel(channel)
    }

    private fun playInternal(source: String, title: String?, displayPath: String?) {
        handler.removeCallbacks(ticker)
        releasePlayer()

        currentSource = source
        currentDisplayPath = displayPath ?: source
        currentTitle = title?.takeIf { it.isNotBlank() } ?: "Meeting Audio"
        isPreparing = true

        persistState()
        updatePlaybackState()
        startForegroundSafely(buildNotification())

        mediaPlayer = MediaPlayer().apply {
            setWakeMode(applicationContext, PowerManager.PARTIAL_WAKE_LOCK)
            setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build(),
            )
            setOnPreparedListener {
                isPreparing = false
                applyPlaybackSpeed()
                start()
                persistState()
                updatePlaybackState()
                startTicker()
                updateNotification()
            }
            setOnCompletionListener {
                handleCompletion()
            }
            setOnErrorListener { _, _, _ ->
                handlePlaybackFailure()
                true
            }

            try {
                setDataSource(source)
                prepareAsync()
            } catch (_: Exception) {
                handlePlaybackFailure()
            }
        }
    }

    private fun pauseInternal() {
        val player = mediaPlayer ?: return
        if (isPreparing || !isPlaying()) {
            return
        }

        runCatching { player.pause() }
        persistState()
        updatePlaybackState()
        updateNotification()
    }

    private fun resumeInternal() {
        val player = mediaPlayer ?: return
        if (isPreparing || isPlaying()) {
            return
        }

        runCatching {
            applyPlaybackSpeed()
            player.start()
        }
        startTicker()
        persistState()
        updatePlaybackState()
        updateNotification()
    }

    private fun stopInternal() {
        handler.removeCallbacks(ticker)
        releasePlayer()
        clearSessionState()
        persistState()
        updatePlaybackState()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun seekInternal(positionMs: Long) {
        val player = mediaPlayer ?: return
        if (isPreparing) {
            return
        }

        val safePosition = positionMs.coerceAtLeast(0L)
        runCatching { player.seekTo(safePosition.toInt()) }
        persistState()
        updatePlaybackState()
        updateNotification()
    }

    private fun setSpeedInternal(speed: Float) {
        playbackSpeed = speed.coerceIn(0.5f, 2.0f)
        applyPlaybackSpeed()
        persistState()
        updatePlaybackState()
        updateNotification()
    }

    private fun applyPlaybackSpeed() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return
        }

        val player = mediaPlayer ?: return
        runCatching {
            player.playbackParams = player.playbackParams.setSpeed(playbackSpeed)
        }
    }

    private fun handleCompletion() {
        handler.removeCallbacks(ticker)
        releasePlayer()
        clearSessionState()
        persistState()
        updatePlaybackState()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun handlePlaybackFailure() {
        handler.removeCallbacks(ticker)
        releasePlayer()
        clearSessionState()
        persistState()
        updatePlaybackState()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun releasePlayer() {
        mediaPlayer?.runCatching { reset() }
        mediaPlayer?.runCatching { release() }
        mediaPlayer = null
        isPreparing = false
    }

    private fun clearSessionState() {
        currentSource = null
        currentDisplayPath = null
        currentTitle = null
    }

    private fun isPlaying(): Boolean = runCatching {
        mediaPlayer?.isPlaying == true
    }.getOrDefault(false)

    private fun isSessionActive(): Boolean =
        currentSource != null && (mediaPlayer != null || isPreparing)

    private fun totalDurationMs(): Long = runCatching {
        val raw = mediaPlayer?.duration ?: 0
        raw.coerceAtLeast(0).toLong()
    }.getOrDefault(0L)

    private fun currentPositionMs(): Long = runCatching {
        val raw = mediaPlayer?.currentPosition ?: 0
        raw.coerceAtLeast(0).toLong()
    }.getOrDefault(0L)

    private fun startTicker() {
        handler.removeCallbacks(ticker)
        handler.post(ticker)
    }

    private fun updateNotification() {
        if (!isSessionActive()) {
            return
        }
        val manager = ContextCompat.getSystemService(this, NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification())
    }

    private fun buildNotification(): Notification {
        val title = currentTitle ?: "Meeting Audio"
        val playing = isPlaying()
        val loading = isPreparing
        val positionMs = currentPositionMs()
        val durationMs = totalDurationMs()
        val contentText = when {
            loading -> "Loading meeting audio..."
            durationMs > 0L -> "${formatDuration(positionMs)} / ${formatDuration(durationMs)}"
            else -> formatDuration(positionMs)
        }

        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                3001,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }

        val playPauseIntent = Intent(this, MeetingPlaybackService::class.java).apply {
            action = if (playing) ACTION_PAUSE else ACTION_RESUME
        }
        val stopIntent = Intent(this, MeetingPlaybackService::class.java).apply {
            action = ACTION_STOP
        }

        val playPausePendingIntent = PendingIntent.getService(
            this,
            3002,
            playPauseIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopPendingIntent = PendingIntent.getService(
            this,
            3003,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setContentTitle(title)
            .setContentText(contentText)
            .setSubText("VVC Meetings")
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_TRANSPORT)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setStyle(
                androidx.media.app.NotificationCompat.MediaStyle()
                    .setMediaSession(mediaSession.sessionToken)
                    .setShowActionsInCompactView(0, 1),
            )
            .addAction(
                NotificationCompat.Action(
                    if (playing) android.R.drawable.ic_media_pause else android.R.drawable.ic_media_play,
                    if (playing) "Pause" else "Play",
                    playPausePendingIntent,
                ),
            )
            .addAction(
                NotificationCompat.Action(
                    android.R.drawable.ic_menu_close_clear_cancel,
                    "Stop",
                    stopPendingIntent,
                ),
            )

        if (contentIntent != null) {
            builder.setContentIntent(contentIntent)
        }

        return builder.build()
    }

    private fun updatePlaybackState() {
        if (!::mediaSession.isInitialized) {
            return
        }

        val state = when {
            isPreparing -> PlaybackStateCompat.STATE_BUFFERING
            isPlaying() -> PlaybackStateCompat.STATE_PLAYING
            isSessionActive() -> PlaybackStateCompat.STATE_PAUSED
            else -> PlaybackStateCompat.STATE_STOPPED
        }

        val actions =
            PlaybackStateCompat.ACTION_PLAY or
                PlaybackStateCompat.ACTION_PLAY_PAUSE or
                PlaybackStateCompat.ACTION_PAUSE or
                PlaybackStateCompat.ACTION_STOP or
                PlaybackStateCompat.ACTION_SEEK_TO

        mediaSession.setPlaybackState(
            PlaybackStateCompat.Builder()
                .setActions(actions)
                .setState(state, currentPositionMs(), playbackSpeed)
                .build(),
        )

        mediaSession.setMetadata(
            MediaMetadataCompat.Builder()
                .putString(MediaMetadata.METADATA_KEY_TITLE, currentTitle ?: "Meeting Audio")
                .putLong(MediaMetadata.METADATA_KEY_DURATION, totalDurationMs())
                .build(),
        )
        mediaSession.isActive = isSessionActive()
    }

    private fun persistState() {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_ACTIVE, isSessionActive())
            .putBoolean(PREF_PLAYING, isPlaying())
            .putBoolean(PREF_LOADING, isPreparing)
            .putString(PREF_PATH, currentDisplayPath)
            .putString(PREF_TITLE, currentTitle)
            .putLong(PREF_DURATION, totalDurationMs())
            .putLong(PREF_POSITION, currentPositionMs())
            .putFloat(PREF_SPEED, playbackSpeed)
            .apply()
    }

    private fun startForegroundSafely(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK,
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
        return if (hours > 0L) {
            String.format(Locale.getDefault(), "%02d:%02d:%02d", hours, minutes, seconds)
        } else {
            String.format(Locale.getDefault(), "%02d:%02d", minutes, seconds)
        }
    }
}
