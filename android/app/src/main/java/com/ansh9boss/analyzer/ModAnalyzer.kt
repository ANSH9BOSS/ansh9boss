package com.ansh9boss.analyzer

import android.content.Context
import android.net.Uri
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class ModAnalyzer(private val context: Context) {

    fun scanJar(uri: Uri, fileName: String, lastModified: Long): ModResult {
        val lowerName = fileName.lowercase()
        var riskLevel = "CLEAN"
        val layers = mutableListOf<String>()
        val details = mutableListOf<String>()
        var obfuscated = false

        // 1. USB/Recent Injection Check
        val hoursDiff = (System.currentTimeMillis() - lastModified) / (3600.0 * 1000.0)
        val isRecent = hoursDiff <= 24.0

        // 2. Layer 1: Filename Check
        for (cheat in Config.knownCheats) {
            if (cheat == "badlion") {
                if (lowerName.contains("badlion") && !lowerName.contains("official") && !lowerName.contains("original")) {
                    if (riskLevel != "DANGEROUS") {
                        riskLevel = "SUSPICIOUS"
                    }
                    layers.add("Layer 1 (Filename)")
                    details.add("Filename contains 'badlion' (Modified verification required)")
                }
            } else if (lowerName.contains(cheat)) {
                riskLevel = "DANGEROUS"
                layers.add("Layer 1 (Filename)")
                details.add("Filename matches known cheat: '$cheat'")
                break
            }
        }

        // 3. Layer 2 & Layer 3: Zip Extraction
        var inputStream: InputStream? = null
        var zipInput: ZipInputStream? = null
        try {
            inputStream = context.contentResolver.openInputStream(uri)
            if (inputStream != null) {
                zipInput = ZipInputStream(inputStream)
                var entry: ZipEntry? = zipInput.nextEntry
                
                var totalClasses = 0
                var shortClassNames = 0
                val matchedStrings = mutableSetOf<String>()

                while (entry != null) {
                    val entryName = entry.name
                    val entryLower = entryName.lowercase()

                    // Count classes for obfuscation check
                    if (entryName.endsWith(".class")) {
                        totalClasses++
                        val nameWithoutExtension = entryName.substringAfterLast('/').substringBeforeLast('.')
                        if (nameWithoutExtension.length <= 2) {
                            shortClassNames++
                        }
                    }

                    // Heuristic protector names
                    val protectorKeywords = listOf("yguard", "allatori", "zelix", "proguard", "stringer", "loaderencrypt")
                    if (protectorKeywords.any { entryLower.contains(it) }) {
                        obfuscated = true
                    }

                    // Layer 2: Package Name Check
                    for (pkg in Config.knownPackages) {
                        if (entryLower.contains("/$pkg/") || entryLower.startsWith("$pkg/")) {
                            riskLevel = "DANGEROUS"
                            if (!layers.contains("Layer 2 (Package)")) {
                                layers.add("Layer 2 (Package)")
                            }
                            details.add("Found cheat package directory: '$pkg' ($entryName)")
                        }
                    }

                    // Layer 2/3: Manifest & File Content Scanner
                    val scannableExtensions = listOf(".class", ".json", ".txt", ".toml", ".properties", ".yml")
                    if (scannableExtensions.any { entryName.endsWith(it) }) {
                        try {
                            val contentString = readEntryText(zipInput)
                            
                            // Check Layer 2 in manifest files
                            if (entryName.endsWith("fabric.mod.json") || entryName.endsWith("mods.toml") || entryName.endsWith("manifest.mf")) {
                                for (pkg in Config.knownPackages) {
                                    if (contentString.contains(pkg)) {
                                        riskLevel = "DANGEROUS"
                                        if (!layers.contains("Layer 2 (Package)")) {
                                            layers.add("Layer 2 (Package)")
                                        }
                                        details.add("Cheat package signature '$pkg' found in manifest: $entryName")
                                    }
                                }
                            }

                            // Layer 3: Cheat Strings check
                            for (cheatStr in Config.cheatStrings) {
                                if (contentString.contains(cheatStr)) {
                                    matchedStrings.add(cheatStr)
                                }
                            }
                        } catch (e: Exception) {
                            // Suppress entry read exceptions
                        }
                    }

                    zipInput.closeEntry()
                    entry = zipInput.nextEntry
                }

                // Heuristic Obfuscation check
                if (totalClasses > 15 && (shortClassNames.toDouble() / totalClasses.toDouble()) > 0.85) {
                    obfuscated = true
                }

                if (obfuscated) {
                    if (riskLevel != "DANGEROUS") {
                        riskLevel = "SUSPICIOUS"
                    }
                    layers.add("Obfuscation Check")
                    details.add("Heavily obfuscated or protected jar file structure")
                }

                // Trigger Layer 3 risk assignment
                if (matchedStrings.isNotEmpty()) {
                    if (matchedStrings.size >= 3) {
                        riskLevel = "DANGEROUS"
                        layers.add("Layer 3 (String Scan)")
                        details.add("Dangerous cheat keywords (${matchedStrings.size} matches): ${matchedStrings.toList()}")
                    } else if (matchedStrings.size == 2) {
                        if (riskLevel != "DANGEROUS") {
                            riskLevel = "SUSPICIOUS"
                        }
                        layers.add("Layer 3 (String Scan)")
                        details.add("Suspicious cheat keywords (${matchedStrings.size} matches): ${matchedStrings.toList()}")
                    }
                }
            }
        } catch (e: Exception) {
            // Obfuscation handling: try fallback extraction (failed zip headers)
            obfuscated = true
            riskLevel = "SUSPICIOUS"
            layers.add("Obfuscation Check")
            details.add("Protected or corrupt JAR structure (Unzip failed: ${e.message})")
        } finally {
            try {
                zipInput?.close()
                inputStream?.close()
            } catch (e: Exception) {}
        }

        if (isRecent && riskLevel != "CLEAN") {
            layers.add("Recent Modification")
            details.add("File was modified/added recently (within 24 hours)")
        }

        if (layers.isEmpty()) {
            riskLevel = "CLEAN"
        }

        return ModResult(riskLevel, layers, details)
    }

    private fun readEntryText(zip: ZipInputStream): String {
        val bos = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        var len = 0
        // Limit max bytes read per entry to prevent memory exhaustion (e.g. zip bomb defence)
        var totalRead = 0
        val maxReadLimit = 256 * 1024 // 256KB limit per class/text file

        while (totalRead < maxReadLimit && zip.read(buffer).also { len = it } != -1) {
            bos.write(buffer, 0, len)
            totalRead += len
        }
        return bos.toString("ISO-8859-1").lowercase()
    }
}

data class ModResult(
    val riskLevel: String,
    val layersTriggered: List<String>,
    val matchedDetails: List<String>
)
