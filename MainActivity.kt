package com.pureadblock.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private val prefs by lazy { getSharedPreferences("pure_adblock", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.rgb(8, 10, 12)
        window.navigationBarColor = Color.rgb(8, 10, 12)
        buildScreen()
    }

    override fun onResume() {
        super.onResume()
        val active = prefs.getBoolean("active", false)
        showState(active, if (active) "DNS protection is running" else "Ads are not blocked")
    }

    private fun buildScreen() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(28, 54, 28, 28)
            setBackgroundColor(Color.rgb(8, 10, 12))
        }
        val title = TextView(this).apply {
            text = "PURE ADBLOCK"
            textSize = 27f
            setTextColor(Color.WHITE)
            typeface = Typeface.create("sans-serif-black", Typeface.BOLD)
            gravity = Gravity.CENTER
        }
        val subtitle = TextView(this).apply {
            text = "ALL-APP DNS PROTECTION"
            textSize = 12f
            letterSpacing = 0.18f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
            setPadding(0, 10, 0, 44)
        }
        status = TextView(this).apply {
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setPadding(0, 18, 0, 18)
        }
        toggle = Button(this).apply {
            textSize = 20f
            text = "⏻   TURN ON"
            setOnClickListener { onToggle() }
        }
        val note = TextView(this).apply {
            text = "Blocks domains on the DNS blocklist.\nSome in-app and server-delivered ads may still appear."
            textSize = 13f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
            setPadding(12, 38, 12, 24)
        }
        val coverage = TextView(this).apply {
            text = "CHROME  •  SOCIAL APPS  •  OTT\nCoverage depends on each app's ad delivery method."
            textSize = 12f
            setTextColor(Color.rgb(180, 190, 190))
            gravity = Gravity.CENTER
        }
        root.addView(title, matchWrap())
        root.addView(subtitle, matchWrap())
        root.addView(status, matchWrap())
        root.addView(toggle, LinearLayout.LayoutParams(-1, 64).apply { topMargin = 18 })
        root.addView(note, matchWrap())
        root.addView(coverage, matchWrap())
        setContentView(root)
    }

    private fun onToggle() {
        if (prefs.getBoolean("active", false)) {
            startService(Intent(this, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_STOP))
            showState(false, "Protection stopped")
        } else {
            val prepare = VpnService.prepare(this)
            if (prepare != null) startActivityForResult(prepare, REQUEST_VPN_PERMISSION) else startProtection()
        }
    }

    @Deprecated("Use of the legacy activity result callback is kept to avoid extra libraries in this starter")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) startProtection()
            else showState(false, "VPN permission was not granted")
        }
    }

    private fun startProtection() {
        val intent = Intent(this, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_START)
        if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        // The service updates this again only after the tunnel is established.
        status.postDelayed({
            val active = prefs.getBoolean("active", false)
            showState(active, if (active) "DNS protection is running" else "Could not start VPN protection")
        }, 700)
    }

    private fun showState(active: Boolean, message: String) {
        status.text = if (active) "●  PROTECTION ON" else "○  PROTECTION OFF"
        status.setTextColor(if (active) Color.rgb(55, 220, 125) else Color.LTGRAY)
        toggle.text = if (active) "⏻   TURN OFF" else "⏻   TURN ON"
        toggle.setTextColor(if (active) Color.rgb(20, 120, 65) else Color.DKGRAY)
        toggle.contentDescription = message
    }

    private fun matchWrap() = LinearLayout.LayoutParams(-1, -2)

    companion object { private const val REQUEST_VPN_PERMISSION = 41 }
}
