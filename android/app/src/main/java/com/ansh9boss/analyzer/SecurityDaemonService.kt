package com.ansh9boss.analyzer

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.documentfile.provider.DocumentFile

class SecurityDaemonService : Service() {

    private val handler = Handler(Looper.getMainLooper())
    private var observeUri: Uri? = null
    private val processedFiles = mutableSetOf<String>()
    private var isRunning = false

    private val checkFolderRunnable = object : Runnable {
        override fun run() {
            val uri = observeUri
            if (uri != null) {
                scanFolderForChanges(uri)
            }
            // Poll every 8 seconds for new mods
            handler.postDelayed(this, 8000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val uriString = intent?.getStringExtra("observe_uri")
        if (uriString != null) {
            observeUri = Uri.parse(uriString)
        }

        val action = intent?.action
        if (action == "STOP_DAEMON") {
            stopForeground(true)
            stopSelf()
            return START_NOT_STICKY
        }

        // Setup foreground notification
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = Intent(this, SecurityDaemonService::class.java).apply {
            this.action = "STOP_DAEMON"
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("CheatsAnalyser Shield")
            .setContentText("Actively monitoring Minecraft mod directory for threats...")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "DISABLE GUARD", stopPendingIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(FOREGROUND_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(FOREGROUND_ID, notification)
        }

        if (!isRunning) {
            // Seed current file state first
            observeUri?.let { seedCurrentFiles(it) }
            handler.post(checkFolderRunnable)
            isRunning = true
        }

        return START_STICKY
    }

    override fun onDestroy() {
        handler.removeCallbacks(checkFolderRunnable)
        isRunning = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun seedCurrentFiles(treeUri: Uri) {
        val rootDoc = DocumentFile.fromTreeUri(this, treeUri)
        if (rootDoc != null) {
            val list = mutableListOf<DocumentFile>()
            gatherJars(rootDoc, list)
            for (doc in list) {
                val uniqueKey = "${doc.name}_${doc.lastModified()}"
                processedFiles.add(uniqueKey)
            }
        }
    }

    private fun scanFolderForChanges(treeUri: Uri) {
        val rootDoc = DocumentFile.fromTreeUri(this, treeUri)
        if (rootDoc != null) {
            val currentJars = mutableListOf<DocumentFile>()
            gatherJars(rootDoc, currentJars)

            val analyzer = ModAnalyzer(this)

            for (doc in currentJars) {
                val name = doc.name ?: "UnknownMod.jar"
                val uniqueKey = "${name}_${doc.lastModified()}"

                if (!processedFiles.contains(uniqueKey)) {
                    // New file detected! Scan immediately
                    processedFiles.add(uniqueKey)
                    val result = analyzer.scanJar(doc.uri, name, doc.lastModified())

                    if (result.riskLevel != "CLEAN") {
                        sendThreatNotification(name, result.riskLevel, result.layersTriggered.joinToString(" & "))
                    }
                }
            }
        }
    }

    private fun gatherJars(directory: DocumentFile, list: MutableList<DocumentFile>) {
        val files = directory.listFiles()
        for (file in files) {
            if (file.isDirectory) {
                gatherJars(file, list)
            } else if (file.isFile && file.name?.endsWith(".jar") == true) {
                list.add(file)
            }
        }
    }

    private fun sendThreatNotification(fileName: String, riskLevel: String, triggers: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val riskPrefix = if (riskLevel == "DANGEROUS") "🔴 DANGEROUS" else "🟡 SUSPICIOUS"
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("MOD THREAT DETECTED")
            .setContentText("$riskPrefix: $fileName contains $triggers")
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                "CheatsAnalyser Security Daemon Guard",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    companion object {
        private const val CHANNEL_ID = "CheatsAnalyserDaemonChannel"
        private const val FOREGROUND_ID = 5005
    }
}
