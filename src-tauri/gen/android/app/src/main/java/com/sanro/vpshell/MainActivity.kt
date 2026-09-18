package com.sanro.vpshell

import android.content.DialogInterface
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

private const val MAX_VISIBILITY_MESSAGE_BYTES = 32
private const val VISIBILITY_BRIDGE_NAME = "vpshellVisibility"
private val VISIBILITY_PRODUCTION_ORIGINS = setOf("http://tauri.localhost")

class MainActivity : TauriActivity() {
  private var appWebView: WebView? = null
  private var activityResumed = false
  private var lockedDialog: AlertDialog? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE,
    )
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    appWebView = webView
    super.onWebViewCreate(webView)
    webView.visibility = View.INVISIBLE
    webView.setFilterTouchesWhenObscured(true)
    webView.setOnLongClickListener { true }
    webView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      webView.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
    }
    webView.settings.allowContentAccess = false
    webView.settings.allowFileAccess = false
    webView.settings.saveFormData = false
    webView.settings.setGeolocationEnabled(false)
    installVisibilityBridge(webView)
  }

  override fun onPause() {
    activityResumed = false
    hideContent()
    dispatchLifecycleEvent("vpshell-native-background")
    super.onPause()
  }

  override fun onResume() {
    super.onResume()
    activityResumed = true
    hideContent()
    dispatchLifecycleEvent("vpshell-native-resume")
  }

  override fun onDestroy() {
    lockedDialog?.dismiss()
    lockedDialog = null
    appWebView = null
    super.onDestroy()
  }

  private fun installVisibilityBridge(webView: WebView) {
    if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return
    val allowedOrigins = if (BuildConfig.DEBUG) {
      VISIBILITY_PRODUCTION_ORIGINS + "http://localhost:1420"
    } else {
      VISIBILITY_PRODUCTION_ORIGINS
    }
    WebViewCompat.addWebMessageListener(
      webView,
      VISIBILITY_BRIDGE_NAME,
      allowedOrigins,
    ) { _, message, sourceOrigin, isMainFrame, _ ->
      if (!isMainFrame || sourceOrigin.toString() !in allowedOrigins) return@addWebMessageListener
      val action = message.data ?: return@addWebMessageListener
      if (action.toByteArray(Charsets.UTF_8).size > MAX_VISIBILITY_MESSAGE_BYTES) {
        return@addWebMessageListener
      }
      when (action) {
        "show" -> if (activityResumed) revealContent()
        "hide" -> hideContent()
        "failed" -> if (activityResumed) showLockedDialog()
      }
    }
  }

  private fun revealContent() {
    lockedDialog?.dismiss()
    lockedDialog = null
    appWebView?.visibility = View.VISIBLE
  }

  private fun hideContent() {
    appWebView?.clearFocus()
    appWebView?.visibility = View.INVISIBLE
  }

  private fun dispatchLifecycleEvent(name: String) {
    appWebView?.evaluateJavascript("window.dispatchEvent(new Event('$name'))", null)
  }

  private fun showLockedDialog() {
    if (lockedDialog?.isShowing == true || isFinishing) return
    lockedDialog = AlertDialog.Builder(this)
      .setTitle("VPShell 已锁定")
      .setMessage("需要通过系统验证才能访问连接与本机凭据。")
      .setCancelable(false)
      .setPositiveButton("重新验证") { _: DialogInterface, _: Int ->
        dispatchLifecycleEvent("vpshell-native-resume")
      }
      .setNegativeButton("退出") { _: DialogInterface, _: Int -> finishAndRemoveTask() }
      .create()
    lockedDialog?.show()
  }
}
