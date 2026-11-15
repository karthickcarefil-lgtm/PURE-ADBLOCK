package com.pureadblock.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Phase-1 DNS-only filtering VPN. This is deliberately not a full traffic VPN:
 * only IPv4 UDP DNS requests to the local VPN DNS address enter this interface.
 */
class AdBlockVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.pureadblock.app.START"
        const val ACTION_STOP = "com.pureadblock.app.STOP"
        private const val CHANNEL_ID = "pure_adblock_vpn"
        private const val VPN_DNS = "10.0.0.1"
        private const val UPSTREAM_DNS = "1.1.1.1"
        private val blockedDomains = setOf(
            "doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "adservice.google.com", "admob.com", "adnxs.com", "taboola.com",
            "outbrain.com", "unityads.unity3d.com", "applovin.com", "inmobi.com",
            "vungle.com", "chartboost.com", "ironsrc.com", "moatads.com",
            "scorecardresearch.com", "adsrvr.org", "criteo.com", "pubmatic.com",
            "rubiconproject.com", "openx.net", "smaato.net", "adsafeprotected.com"
        )
    }

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopProtection()
            return START_NOT_STICKY
        }
        startForeground(7, buildNotification())
        if (!running) startProtection()
        return START_STICKY
    }

    private fun startProtection() {
        val descriptor = Builder()
            .setSession("PURE ADBLOCK")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addDnsServer(VPN_DNS)
            .addRoute(VPN_DNS, 32)
            .establish()

        if (descriptor == null) {
            saveState(false)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        tun = descriptor
        running = true
        saveState(true)
        Thread({ packetLoop(descriptor) }, "PureAdBlock-DNS").start()
    }

    private fun packetLoop(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (running) {
                val count = input.read(buffer)
                if (count <= 0) continue
                val packet = buffer.copyOf(count)
                val response = processDnsPacket(packet) ?: continue
                output.write(response)
                output.flush()
            }
        } catch (_: Exception) {
            // Closing the TUN descriptor is the normal way to end this loop.
        } finally {
            if (running) {
                running = false
                saveState(false)
                stopSelf()
            }
        }
    }

    private fun processDnsPacket(packet: ByteArray): ByteArray? {
        if (packet.size < 28) return null
        if ((packet[0].toInt() and 0xF0) != 0x40) return null
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (ipHeaderLength < 20 || packet.size < ipHeaderLength + 8) return null
        if ((packet[9].toInt() and 0xFF) != 17) return null // UDP only
        val destinationPort = u16(packet, ipHeaderLength + 2)
        if (destinationPort != 53) return null
        val udpLength = u16(packet, ipHeaderLength + 4)
        if (udpLength < 8 || ipHeaderLength + udpLength > packet.size) return null
        val dns = packet.copyOfRange(ipHeaderLength + 8, ipHeaderLength + udpLength)
        val question = parseQuestion(dns) ?: return null
        val answer = if (isBlocked(question.first)) blockedReply(dns, question.second) else forwardDns(dns)
        return answer?.let { wrapIpv4Udp(packet, ipHeaderLength, it) }
    }

    private fun parseQuestion(dns: ByteArray): Pair<String, Int>? {
        if (dns.size < 17) return null
        val questionCount = u16(dns, 4)
        if (questionCount < 1) return null
        var index = 12
        val labels = ArrayList<String>()
        while (index < dns.size) {
            val length = dns[index].toInt() and 0xFF
            if (length == 0) { index++; break }
            // Compression pointers are not valid in a standard question name.
            if ((length and 0xC0) != 0 || length > 63 || index + 1 + length > dns.size) return null
            labels += String(dns, index + 1, length, Charsets.US_ASCII)
            index += length + 1
        }
        val end = index + 4
        if (labels.isEmpty() || end > dns.size) return null
        return labels.joinToString(".").lowercase() to end
    }

    private fun isBlocked(host: String): Boolean {
        var candidate = host.trimEnd('.')
        while (candidate.isNotEmpty()) {
            if (candidate in blockedDomains) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) break
            candidate = candidate.substring(dot + 1)
        }
        return false
    }

    private fun blockedReply(query: ByteArray, questionEnd: Int): ByteArray {
        val reply = query.copyOf(questionEnd)
        reply[2] = 0x81.toByte() // response + recursion desired
        reply[3] = 0x83.toByte() // recursion available + NXDOMAIN
        reply[6] = 0; reply[7] = 0
        reply[8] = 0; reply[9] = 0
        reply[10] = 0; reply[11] = 0
        return reply
    }

    private fun forwardDns(query: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        return try {
            if (!protect(socket)) return null
            socket.soTimeout = 3500
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(UPSTREAM_DNS), 53))
            val response = ByteArray(4096)
            val received = DatagramPacket(response, response.size)
            socket.receive(received)
            response.copyOf(received.length)
        } catch (_: Exception) {
            null
        } finally {
            socket.close()
        }
    }

    private fun wrapIpv4Udp(original: ByteArray, ipHeaderLength: Int, dns: ByteArray): ByteArray {
        val totalLength = 20 + 8 + dns.size
        val result = ByteArray(totalLength)
        result[0] = 0x45
        result[2] = (totalLength shr 8).toByte(); result[3] = totalLength.toByte()
        result[8] = 64; result[9] = 17
        System.arraycopy(original, 16, result, 12, 4) // reply source = request destination
        System.arraycopy(original, 12, result, 16, 4) // reply destination = request source
        val ipChecksum = checksum(result, 0, 20)
        result[10] = (ipChecksum shr 8).toByte(); result[11] = ipChecksum.toByte()
        result[20] = original[ipHeaderLength + 2]
        result[21] = original[ipHeaderLength + 3]
        result[22] = original[ipHeaderLength]
        result[23] = original[ipHeaderLength + 1]
        val udpLength = 8 + dns.size
        result[24] = (udpLength shr 8).toByte(); result[25] = udpLength.toByte()
        // A zero UDP checksum is permitted for IPv4.
        System.arraycopy(dns, 0, result, 28, dns.size)
        return result
    }

    private fun checksum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        while (i + 1 < offset + length) {
            sum += (((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < offset + length) sum += ((bytes[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun u16(bytes: ByteArray, index: Int): Int =
        ((bytes[index].toInt() and 0xFF) shl 8) or (bytes[index + 1].toInt() and 0xFF)

    private fun stopProtection() {
        running = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        saveState(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopProtection()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopProtection()
        super.onDestroy()
    }

    private fun saveState(active: Boolean) {
        getSharedPreferences("pure_adblock", MODE_PRIVATE).edit().putBoolean("active", active).apply()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL_ID, "PURE ADBLOCK", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val stopIntent = Intent(this, AdBlockVpnService::class.java).setAction(ACTION_STOP)
        val pending = PendingIntent.getService(this, 2, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
        return builder.setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("PURE ADBLOCK is active")
            .setContentText("DNS-based ad and tracker filtering is running")
            .setOngoing(true)
            .addAction(android.R.drawable.ic_media_pause, "Turn off", pending)
            .build()
    }
}
