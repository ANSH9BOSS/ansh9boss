package com.ansh9boss.analyzer

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class ScanHistoryDbHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        const val DATABASE_NAME = "scan_history.db"
        const val DATABASE_VERSION = 1
        
        const val TABLE_NAME = "local_scans"
        const val COLUMN_ID = "id"
        const val COLUMN_TIMESTAMP = "timestamp"
        const val COLUMN_TOTAL_FILES = "total_files"
        const val COLUMN_FLAGGED_FILES = "flagged_files"
        const val COLUMN_HIGHEST_RISK = "highest_risk"
    }

    override fun onCreate(db: SQLiteDatabase) {
        val createTableQuery = """
            CREATE TABLE $TABLE_NAME (
                $COLUMN_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COLUMN_TIMESTAMP DATETIME DEFAULT CURRENT_TIMESTAMP,
                $COLUMN_TOTAL_FILES INTEGER,
                $COLUMN_FLAGGED_FILES INTEGER,
                $COLUMN_HIGHEST_RISK TEXT
            )
        """.trimIndent()
        db.execSQL(createTableQuery)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_NAME")
        onCreate(db)
    }

    fun addScan(totalFiles: Int, flaggedFiles: Int, highestRisk: String) {
        try {
            val db = writableDatabase
            val values = ContentValues().apply {
                put(COLUMN_TOTAL_FILES, totalFiles)
                put(COLUMN_FLAGGED_FILES, flaggedFiles)
                put(COLUMN_HIGHEST_RISK, highestRisk)
            }
            db.insert(TABLE_NAME, null, values)
            db.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getScanHistory(): List<LocalScanRecord> {
        val list = mutableListOf<LocalScanRecord>()
        try {
            val db = readableDatabase
            val cursor = db.rawQuery("SELECT * FROM $TABLE_NAME ORDER BY id DESC LIMIT 5", null)
            if (cursor.moveToFirst()) {
                do {
                    val timestamp = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_TIMESTAMP))
                    val total = cursor.getInt(cursor.getColumnIndexOrThrow(COLUMN_TOTAL_FILES))
                    val flagged = cursor.getInt(cursor.getColumnIndexOrThrow(COLUMN_FLAGGED_FILES))
                    val risk = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_HIGHEST_RISK))
                    list.add(LocalScanRecord(timestamp, total, flagged, risk))
                } while (cursor.moveToNext())
            }
            cursor.close()
            db.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
    }
}

data class LocalScanRecord(
    val timestamp: String,
    val totalFiles: Int,
    val flaggedFiles: Int,
    val highestRisk: String
)
