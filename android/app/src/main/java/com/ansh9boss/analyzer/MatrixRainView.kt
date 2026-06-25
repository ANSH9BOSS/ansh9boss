package com.ansh9boss.analyzer

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import java.util.Random

class MatrixRainView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null, defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val textPaint = Paint()
    private val random = Random()
    private var width = 0
    private var height = 0
    private var fontSize = 40f
    private var columns = 0
    private lateinit var drops: IntArray

    // Classic Matrix characters
    private val chars = "010101010101101010101010101010101"

    init {
        textPaint.color = Color.parseColor("#33FFFFFF") // Subtle white code rain
        textPaint.textSize = fontSize
        textPaint.isAntiAlias = true
        textPaint.typeface = android.graphics.Typeface.MONOSPACE
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        width = w
        height = h
        columns = (width / fontSize).toInt() + 1
        drops = IntArray(columns) { random.nextInt(height) }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        
        // Draw semi-transparent black background to create trail effect
        canvas.drawColor(Color.parseColor("#11000000"))

        for (i in 0 until columns) {
            val char = chars[random.nextInt(chars.length)].toString()
            val x = i * fontSize
            val y = drops[i] * fontSize

            // Randomly highlight some characters in pure white
            if (random.nextFloat() > 0.95f) {
                textPaint.color = Color.WHITE
            } else {
                textPaint.color = Color.parseColor("#33FFFFFF")
            }

            canvas.drawText(char, x, y, textPaint)

            // Reset drop to top with random delay if it goes off screen
            if (y > height && random.nextFloat() > 0.975f) {
                drops[i] = 0
            }

            // Move drop down
            drops[i]++
        }

        // Force redraw at roughly ~30fps for smooth rain
        postInvalidateDelayed(33)
    }
}
