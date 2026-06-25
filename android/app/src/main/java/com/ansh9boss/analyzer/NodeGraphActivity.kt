package com.ansh9boss.analyzer

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class NodeGraphActivity : AppCompatActivity() {

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Create a programmatic WebView for the 3D Node Graph
        val webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.useWideViewPort = true
            settings.loadWithOverviewMode = true
            // Hardware acceleration is required for WebGL
            setLayerType(android.view.View.LAYER_TYPE_HARDWARE, null)
            
            webViewClient = WebViewClient()
            webChromeClient = WebChromeClient()
        }

        setContentView(webView)

        // Load the local graph HTML or the public Vercel endpoint
        // Using the public website endpoint that has the decompiler graph logic
        webView.loadUrl("https://ansh9boss.vercel.app/#checker")
    }
}
