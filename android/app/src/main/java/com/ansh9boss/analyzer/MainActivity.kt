package com.ansh9boss.analyzer

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.documentfile.provider.DocumentFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import android.view.animation.Animation
import android.view.animation.LinearInterpolator
import android.view.animation.RotateAnimation
import android.view.animation.ScaleAnimation
import android.widget.ImageView

class MainActivity : AppCompatActivity() {

    private lateinit var btnSelectFolder: Button
    private lateinit var btnStartScan: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var tvConsole: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var ivScannerLogo: ImageView
    private lateinit var viewGlowRing: View
    private lateinit var tvCurrentFileName: TextView
    private lateinit var dbHelper: ScanHistoryDbHelper

    private var selectedFolderUri: Uri? = null
    private val executor = Executors.newSingleThreadExecutor()

    companion object {
        private const val REQUEST_CODE_SAF = 1001
    }

    override fun onCreate(Bundle: Bundle?) {
        super.onCreate(Bundle)
        setContentView(R.layout.activity_main)

        btnSelectFolder = findViewById(R.id.btnSelectFolder)
        btnStartScan = findViewById(R.id.btnStartScan)
        progressBar = findViewById(R.id.progressBar)
        tvConsole = findViewById(R.id.tvConsole)
        scrollView = findViewById(R.id.scrollView)
        ivScannerLogo = findViewById(R.id.ivScannerLogo)
        viewGlowRing = findViewById(R.id.viewGlowRing)
        tvCurrentFileName = findViewById(R.id.tvCurrentFileName)

        val btnToggleDaemon = findViewById<Button>(R.id.btnToggleDaemon)
        var daemonActive = false

        btnToggleDaemon.setOnClickListener {
            val uri = selectedFolderUri
            if (uri == null) {
                logToConsole("<font color='#EF4444'>! Linked mods directory required to enable daemon.</font>", true)
            } else {
                if (!daemonActive) {
                    val serviceIntent = Intent(this, SecurityDaemonService::class.java).apply {
                        putExtra("observe_uri", uri.toString())
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        startForegroundService(serviceIntent)
                    } else {
                        startService(serviceIntent)
                    }
                    daemonActive = true
                    btnToggleDaemon.text = "DAEMON GUARD: ACTIVE"
                    btnToggleDaemon.setTextColor(android.graphics.Color.parseColor("#10B981"))
                    logToConsole("<font color='#10B981'>✓ Security Daemon Guard running in background.</font>", true)
                } else {
                    val stopIntent = Intent(this, SecurityDaemonService::class.java).apply {
                        action = "STOP_DAEMON"
                    }
                    startService(stopIntent)
                    daemonActive = false
                    btnToggleDaemon.text = "DAEMON GUARD: INACTIVE"
                    btnToggleDaemon.setTextColor(android.graphics.Color.parseColor("#A1A1AA"))
                    logToConsole("<font color='#71717A'>! Security Daemon Guard disabled.</font>", true)
                }
            }
        }

        dbHelper = ScanHistoryDbHelper(this)
        startIdleGlowAnimation()
        syncThreatRulesAndDisplayHistory()

        btnSelectFolder.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
                // Hint Android system where to open, default to SDCard
                putExtra("android.provider.extra.INITIAL_URI", Uri.parse("content://com.android.externalstorage.documents/document/primary%3AAndroid%2Fdata"))
            }
            startActivityForResult(intent, REQUEST_CODE_SAF)
        }

        btnStartScan.setOnClickListener {
            val uri = selectedFolderUri
            if (uri != null) {
                startScanning(uri)
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CODE_SAF && resultCode == Activity.RESULT_OK) {
            val treeUri = data?.data
            if (treeUri != null) {
                selectedFolderUri = treeUri
                
                // Persist permissions across device reboots
                val takeFlags: Int = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                contentResolver.takePersistableUriPermission(treeUri, takeFlags)

                logToConsole("linked directory: ${treeUri.path}<br><font color='#CCCCCC'>Ready to scan. Click 'Start Scan'.</font>", true)
                tvCurrentFileName.text = "DIRECTORY LINKED"
                btnStartScan.isEnabled = true
            }
        }
    }

    private fun startScanning(treeUri: Uri) {
        btnStartScan.isEnabled = false
        btnSelectFolder.isEnabled = false
        progressBar.visibility = View.VISIBLE
        progressBar.isIndeterminate = true
        tvConsole.text = ""
        tvCurrentFileName.text = "INITIALIZING SCANNER..."
        logToConsole("<b><font color='#FFFFFF'>Initializing CheatsAnalyser Engine by ANSH9BOSS v${Config.VERSION}...</font></b>", true)
        logToConsole("<font color='#A1A1AA'>Platform: ANDROID (Scoped Storage SAF Bypass)</font>", true)
        logToConsole("<font color='#A1A1AA'>Scanning folder hierarchy, please wait...</font>", true)

        startScanGlowAnimation()

        executor.execute {
            try {
                val rootDoc = DocumentFile.fromTreeUri(this, treeUri)
                val jarFiles = mutableListOf<DocumentFile>()
                
                // Traverse directory and gather JAR files
                if (rootDoc != null) {
                    findJarFilesRecursively(rootDoc, jarFiles)
                }

                val totalJars = jarFiles.size
                runOnUiThread {
                    tvCurrentFileName.text = "FOUND $totalJars MOD FILES"
                    logToConsole("<font color='#FFFFFF'>Found $totalJars mod jar file(s) to analyze.</font>", true)
                    progressBar.isIndeterminate = false
                    progressBar.max = totalJars
                    progressBar.progress = 0
                }

                val analyzer = ModAnalyzer(this)
                val detections = mutableListOf<ModDetection>()
                var totalFlagged = 0
                var highestRisk = "CLEAN"

                for ((index, docFile) in jarFiles.withIndex()) {
                    val name = docFile.name ?: "UnknownMod.jar"
                    runOnUiThread {
                        tvCurrentFileName.text = "SCANNING: $name"
                        logToConsole("<font color='#71717A'>[$index/$totalJars]</font> Scanning <font color='#FFFFFF'>$name</font>...", true)
                    }

                    val scanResult = analyzer.scanJar(docFile.uri, name, docFile.lastModified())

                    if (scanResult.riskLevel != "CLEAN") {
                        totalFlagged++
                        if (scanResult.riskLevel == "DANGEROUS") {
                            highestRisk = "DANGEROUS"
                        } else if (scanResult.riskLevel == "SUSPICIOUS" && highestRisk != "DANGEROUS") {
                            highestRisk = "SUSPICIOUS"
                        }

                        detections.add(
                            ModDetection(
                                file_name = name,
                                risk_level = scanResult.riskLevel,
                                detection_layer = scanResult.layersTriggered.joinToString(" & "),
                                matched_details = scanResult.matchedDetails
                            )
                        )

                        runOnUiThread {
                            val isDangerous = scanResult.riskLevel == "DANGEROUS"
                            val prefix = if (isDangerous) "<font color='#EF4444'><b>🔴 DANGEROUS</b></font>" else "<font color='#F59E0B'><b>🟡 SUSPICIOUS</b></font>"
                            logToConsole("   ↳ $prefix: <font color='#FFFFFF'>${scanResult.layersTriggered.joinToString(" & ")}</font>", true)
                            for (detail in scanResult.matchedDetails) {
                                logToConsole("     <font color='#71717A'>- $detail</font>", true)
                            }
                        }
                    }

                    runOnUiThread {
                        progressBar.progress = index + 1
                    }
                }

                // Finalize scan logs
                runOnUiThread {
                    val riskColored = if (highestRisk == "DANGEROUS") "<font color='#EF4444'><b>🔴 DANGEROUS</b></font>" else if (highestRisk == "SUSPICIOUS") "<font color='#F59E0B'><b>🟡 SUSPICIOUS</b></font>" else "<font color='#10B981'><b>🟢 CLEAN</b></font>"
                    logToConsole("<br><b><font color='#FFFFFF'>Scan complete.</font></b> Flagged <font color='#EF4444'><b>$totalFlagged</b></font> threat(s) out of <font color='#FFFFFF'>$totalJars</font> files.", true)
                    logToConsole("Highest Threat Level: $riskColored", true)
                    logToConsole("<font color='#A1A1AA'>Reporting telemetry to central server...</font>", true)
                    dbHelper.addScan(totalJars, totalFlagged, highestRisk)
                }

                // Report stats to global Vercel server
                val reported = reportScanToServer(totalJars, totalFlagged, highestRisk, detections)
                runOnUiThread {
                    ivScannerLogo.clearAnimation()
                    startIdleGlowAnimation()
                    tvCurrentFileName.text = "COMPLETED. FLAGGED $totalFlagged THREATS"

                    if (reported) {
                        logToConsole("<font color='#10B981'>✓ Telemetry successfully reported globally to central server.</font>", true)
                    } else {
                        logToConsole("<font color='#F59E0B'>! Telemetry reporting failed. (Server offline or offline mode)</font>", true)
                    }
                    
                    btnStartScan.isEnabled = true
                    btnSelectFolder.isEnabled = true
                    progressBar.visibility = View.GONE
                }

            } catch (e: Exception) {
                runOnUiThread {
                    ivScannerLogo.clearAnimation()
                    startIdleGlowAnimation()
                    tvCurrentFileName.text = "SCAN ERROR"

                    logToConsole("<font color='#EF4444'><b>[ERROR]</b> Scan task execution failed: ${e.message}</font>", true)
                    btnStartScan.isEnabled = true
                    btnSelectFolder.isEnabled = true
                    progressBar.visibility = View.GONE
                }
            }
        }
    }

    private fun findJarFilesRecursively(directory: DocumentFile, outList: MutableList<DocumentFile>) {
        val files = directory.listFiles()
        for (file in files) {
            if (file.isDirectory) {
                findJarFilesRecursively(file, outList)
            } else if (file.isFile && file.name?.endsWith(".jar") == true) {
                outList.add(file)
            }
        }
    }

    private fun reportScanToServer(totalFiles: Int, flaggedFiles: Int, highestRisk: String, detections: List<ModDetection>): Boolean {
        try {
            val url = URL("${Config.DEFAULT_API_URL}/api/report_scan")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 5000
            conn.readTimeout = 5000

            // Construct JSON Payload
            val payload = JSONObject().apply {
                put("platform", "Android App (Kotlin)")
                put("device_name", android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL)
                put("total_files", totalFiles)
                put("flagged_files", flaggedFiles)
                put("highest_risk", highestRisk)

                val detectionsArray = JSONArray()
                for (det in detections) {
                    val detObject = JSONObject().apply {
                        put("file_name", det.file_name)
                        put("risk_level", det.risk_level)
                        put("detection_layer", det.detection_layer)
                        put("matched_details", JSONArray(det.matched_details))
                    }
                    detectionsArray.put(detObject)
                }
                put("detections", detectionsArray)
            }

            val writer = OutputStreamWriter(conn.outputStream)
            writer.write(payload.toString())
            writer.flush()
            writer.close()

            val responseCode = conn.responseCode
            conn.disconnect()
            return responseCode == 200
        } catch (e: Exception) {
            return false
        }
    }

    private fun logToConsole(message: String, isHtml: Boolean = false) {
        runOnUiThread {
            if (isHtml) {
                tvConsole.append(android.text.Html.fromHtml(message + "<br>", android.text.Html.FROM_HTML_MODE_LEGACY))
            } else {
                tvConsole.append(message + "\n")
            }
            scrollView.post {
                scrollView.fullScroll(View.FOCUS_DOWN)
            }
        }
    }

    private fun startIdleGlowAnimation() {
        val pulseAnim = ScaleAnimation(
            0.95f, 1.05f, 0.95f, 1.05f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f
        ).apply {
            duration = 1800
            repeatMode = Animation.REVERSE
            repeatCount = Animation.INFINITE
            interpolator = LinearInterpolator()
        }
        viewGlowRing.startAnimation(pulseAnim)
    }

    private fun startScanGlowAnimation() {
        val rotateAnim = RotateAnimation(
            0f, 360f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f
        ).apply {
            duration = 2000
            repeatCount = Animation.INFINITE
            interpolator = LinearInterpolator()
        }
        ivScannerLogo.startAnimation(rotateAnim)

        val fastPulse = ScaleAnimation(
            0.9f, 1.1f, 0.9f, 1.1f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f
        ).apply {
            duration = 800
            repeatMode = Animation.REVERSE
            repeatCount = Animation.INFINITE
            interpolator = LinearInterpolator()
        }
        viewGlowRing.startAnimation(fastPulse)
    }

    private fun syncThreatRulesAndDisplayHistory() {
        logToConsole("<b><font color='#FFFFFF'>Checking local scan history cache...</font></b>", true)
        val history = dbHelper.getScanHistory()
        if (history.isEmpty()) {
            logToConsole("<font color='#71717A'>No past local scans found. System ready.</font>", true)
        } else {
            logToConsole("<font color='#FFFFFF'><b>=== LOCAL SCAN AUDIT LOGS ===</b></font>", true)
            for (rec in history) {
                val statusColor = if (rec.highestRisk == "DANGEROUS") "#EF4444" else if (rec.highestRisk == "SUSPICIOUS") "#F59E0B" else "#10B981"
                logToConsole("  <font color='#71717A'>[${rec.timestamp}]</font> Scanned: <font color='#FFFFFF'>${rec.totalFiles}</font> | Flagged: <font color='#EF4444'>${rec.flaggedFiles}</font> | Status: <font color='${statusColor}'><b>${rec.highestRisk}</b></font>", true)
            }
            logToConsole("<font color='#FFFFFF'><b>=============================</b></font><br>", true)
        }

        logToConsole("<font color='#A1A1AA'>Connecting to cloud server for rule updates...</font>", true)
        executor.execute {
            try {
                val url = URL("${Config.DEFAULT_API_URL}/api/rules")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.connectTimeout = 3000
                conn.readTimeout = 3000
                if (conn.responseCode == 200) {
                    val response = conn.inputStream.bufferedReader().use { it.readText() }
                    val json = JSONObject(response)
                    
                    val cheatsArray = json.getJSONArray("known_cheats")
                    val packagesArray = json.getJSONArray("known_packages")
                    val stringsArray = json.getJSONArray("cheat_strings")

                    val newCheats = mutableListOf<String>()
                    for (i in 0 until cheatsArray.length()) {
                        newCheats.add(cheatsArray.getString(i))
                    }
                    val newPackages = mutableListOf<String>()
                    for (i in 0 until packagesArray.length()) {
                        newPackages.add(packagesArray.getString(i))
                    }
                    val newStrings = mutableListOf<String>()
                    for (i in 0 until stringsArray.length()) {
                        newStrings.add(stringsArray.getString(i))
                    }

                    Config.knownCheats = newCheats
                    Config.knownPackages = newPackages
                    Config.cheatStrings = newStrings

                    runOnUiThread {
                        logToConsole("<font color='#10B981'>✓ Dynamic Cloud Rules synced successfully (v${json.getString("version")}).</font>", true)
                    }
                } else {
                    runOnUiThread {
                        logToConsole("<font color='#F59E0B'>! Failed to sync cloud rules. Running local database fallback.</font>", true)
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    logToConsole("<font color='#71717A'>! Cloud rules server unreachable. Running offline signature cache.</font>", true)
                }
            }
        }
    }
}
