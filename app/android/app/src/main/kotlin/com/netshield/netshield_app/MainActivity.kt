package com.netshield.netshield_app

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Notification
import android.app.PendingIntent
import android.os.Build
import android.content.Intent
import android.net.VpnService
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.InetNetwork
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

private object VpnEngine {
    @Volatile private var instance: GoBackend? = null
    fun backend(context: android.content.Context): GoBackend = instance ?: synchronized(this) {
        instance ?: GoBackend(context.applicationContext).also { instance = it }
    }
    val tunnel = object : Tunnel {
        override fun getName() = "netshield"
        override fun onStateChange(newState: Tunnel.State) { }
    }
}

class MainActivity : FlutterActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private var pending: Pair<String, MethodChannel.Result>? = null
    private val backend by lazy { VpnEngine.backend(applicationContext) }
    private val tunnel get() = VpnEngine.tunnel
    private val prefs by lazy { getSharedPreferences("netshield_private", MODE_PRIVATE) }

    override fun configureFlutterEngine(engine: FlutterEngine) {
        super.configureFlutterEngine(engine)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(NotificationChannel("security_alerts", "Alertas de seguridad", NotificationManager.IMPORTANCE_DEFAULT))
        }
        MethodChannel(engine.dartExecutor.binaryMessenger, "netshield/android_vpn").setMethodCallHandler { call, result ->
            when (call.method) {
                "notification" -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        result.success(null)
                    } else {
                        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
                        @Suppress("DEPRECATION")
                        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, "security_alerts") else Notification.Builder(this)
                        val notification = builder
                            .setSmallIcon(android.R.drawable.ic_dialog_alert)
                            .setContentTitle("NetShield VPN")
                            .setContentText("Tienes una alerta de seguridad nueva. Abre NetShield para revisarla.")
                            .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
                            .setAutoCancel(true).build()
                        manager.notify(8001, notification)
                        result.success(null)
                    }
                }
                "identity" -> runAsync(result) {
                    val account = call.argument<String>("account") ?: error("Missing account")
                    mapOf("deviceId" to deviceId(), "publicKey" to accountKey(account).publicKey.toBase64())
                }
                "deviceId" -> runAsync(result) { deviceId() }
                "isConnected" -> runAsync(result) { backend.getState(tunnel) == Tunnel.State.UP }
                "usage" -> runAsync(result) {
                    if (backend.getState(tunnel) != Tunnel.State.UP) null
                    else backend.getStatistics(tunnel).let { mapOf("received" to it.totalRx(), "sent" to it.totalTx()) }
                }
                "disconnect" -> runAsync(result) { backend.setState(tunnel, Tunnel.State.DOWN, null); null }
                "connect" -> {
                    val account = call.argument<String>("account")
                    val template = call.argument<String>("template")
                    if (account == null || template == null || pending != null) {
                        result.error("invalid", "No se pudo preparar el túnel.", null)
                    } else {
                        val permission = VpnService.prepare(this)
                        if (permission != null) {
                            pending = Pair("$account\n$template", result)
                            @Suppress("DEPRECATION")
                            startActivityForResult(permission, 5198)
                        } else startTunnel(account, template, result)
                    }
                }
                else -> result.notImplemented()
            }
        }
    }

    @Deprecated("Android activity result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 5198) return
        val request = pending ?: return
        pending = null
        if (resultCode != Activity.RESULT_OK) {
            request.second.error("permission", "No se autorizó la conexión VPN.", null)
            return
        }
        val parts = request.first.split('\n', limit = 2)
        startTunnel(parts[0], parts[1], request.second)
    }

    private fun startTunnel(account: String, template: String, result: MethodChannel.Result) = runAsync(result) {
        val key = accountKey(account).privateKey.toBase64()
        val placeholder = Regex("(?m)^PrivateKey\\s*=\\s*REPLACE_ME\\s*$")
        require(placeholder.findAll(template).count() == 1)
        require(Regex("(?m)^AllowedIPs\\s*=.*0\\.0\\.0\\.0/0.*::/0\\s*$").containsMatchIn(template))
        val config = Config.parse(placeholder.replaceFirst(template, "PrivateKey = $key").byteInputStream())
        require(config.peers.size == 1)
        require(config.peers[0].allowedIps.containsAll(setOf(InetNetwork.parse("0.0.0.0/0"), InetNetwork.parse("::/0"))))
        require(config.`interface`.includedApplications.isEmpty() && config.`interface`.excludedApplications.isEmpty())
        backend.setState(tunnel, Tunnel.State.UP, config)
        null
    }

    private fun runAsync(result: MethodChannel.Result, block: () -> Any?) {
        executor.execute {
            try {
                val value = block()
                runOnUiThread { result.success(value) }
            } catch (_: Exception) {
                runOnUiThread { result.error("vpn", "No se pudo completar la operación VPN en Android.", null) }
            }
        }
    }

    private fun deviceId(): String {
        prefs.getString("device_id", null)?.let { return it }
        val id = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        check(prefs.edit().putString("device_id", id).commit())
        return id
    }

    private fun accountKey(account: String): KeyPair {
        require(account.isNotEmpty() && account.length <= 128)
        val id = MessageDigest.getInstance("SHA-256").digest(account.toByteArray()).joinToString("") { "%02x".format(it) }
        val stored = prefs.getString("key_$id", null)
        if (stored != null) {
            val bytes = Base64.decode(stored, Base64.NO_WRAP)
            require(bytes.size > 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
            return KeyPair(Key.fromBase64(String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8)))
        }
        val pair = KeyPair()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
        val encrypted = cipher.iv + cipher.doFinal(pair.privateKey.toBase64().toByteArray())
        check(prefs.edit().putString("key_$id", Base64.encodeToString(encrypted, Base64.NO_WRAP)).commit())
        return pair
    }

    private fun encryptionKey(): javax.crypto.SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val name = "netshield_wireguard_keys"
        (store.getKey(name, null) as? javax.crypto.SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        return generator.generateKey()
    }
}
