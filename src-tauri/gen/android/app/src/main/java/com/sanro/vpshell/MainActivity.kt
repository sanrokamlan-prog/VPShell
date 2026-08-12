package com.sanro.vpshell

import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  private var appWebView: WebView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE
    )
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    appWebView = webView
    super.onWebViewCreate(webView)
  }

  override fun onPause() {
    appWebView?.evaluateJavascript("window.dispatchEvent(new Event('vpshell-native-background'))", null)
    super.onPause()
  }

  override fun onResume() {
    super.onResume()
    appWebView?.evaluateJavascript("window.dispatchEvent(new Event('vpshell-native-foreground'))", null)
  }
}
