package com.ansh9boss.analyzer

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
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

        startIdleGlowAnimation()

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

                logToConsole("linked directory: ${treeUri.path}\nReady to scan. Click 'Start Scan'.")
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
        logToConsole("Initializing ANSH9BOSS Android Engine v${Config.VERSION}...")
        logToConsole("Platform: ANDROID (Scoped Storage SAF Bypass)")
        logToConsole("Scanning folder hierarchy, please wait...\n")

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
                    logToConsole("Found $totalJars mod jar file(s) to analyze.")
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
                        logToConsole("[$index/$totalJars] Scanning $name...")
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
                            val prefix = if (scanResult.riskLevel == "DANGEROUS") "🔴 DANGEROUS" else "🟡 SUSPICIOUS"
                            logToConsole("   ↳ $prefix: ${scanResult.layersTriggered.joinToString(" & ")}")
                            for (detail in scanResult.matchedDetails) {
                                logToConsole("     - $detail")
                            }
                        }
                    }

                    runOnUiThread {
                        progressBar.progress = index + 1
                    }
                }

                // Finalize scan logs
                runOnUiThread {
                    logToConsole("\nScan complete. Flagged $totalFlagged threat(s) out of $totalJars scanned files.")
                    logToConsole("Highest Threat Level: $highestRisk")
                    logToConsole("\nReporting anonymous telemetry to central server...")
                }

                // Report stats to global Vercel server
                val reported = reportScanToServer(totalJars, totalFlagged, highestRisk, detections)
                runOnUiThread {
                    ivScannerLogo.clearAnimation()
                    startIdleGlowAnimation()
                    tvCurrentFileName.text = "COMPLETED. FLAGGED $totalFlagged THREATS"

                    if (reported) {
                        logToConsole("✓ Telemetry successfully reported globally to https://ansh9boss.vercel.app")
                    } else {
                        logToConsole("! Telemetry reporting failed. (Server offline or internet unavailable)")
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

                    logToConsole("Error during scan task execution: ${e.message}")
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

    private fun logToConsole(message: String) {
        tvConsole.append(message + "\n")
        scrollView.post {
            scrollView.fullScroll(View.FOCUS_DOWN)
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
}
