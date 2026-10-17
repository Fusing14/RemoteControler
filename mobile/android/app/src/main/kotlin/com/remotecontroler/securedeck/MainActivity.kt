package com.remotecontroler.securedeck

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Base64
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.File

class MainActivity : FlutterActivity() {

    companion object {
        private const val INSTALLER_CHANNEL = "com.remotecontroler.securedeck/installer"
        private const val MIC_METHOD_CHANNEL = "com.remotecontroler.securedeck/mic"
        private const val MIC_EVENT_CHANNEL = "com.remotecontroler.securedeck/mic_stream"
        private const val RECORD_AUDIO_REQ_CODE = 2001
    }

    @Volatile
    private var isRecording = false
    private var audioRecord: AudioRecord? = null
    private var recordingThread: Thread? = null
    private var micEventSink: EventChannel.EventSink? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // 1. Canal de instalación nativa con AndroidX FileProvider
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, INSTALLER_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "installApk" -> {
                    val filePath = call.argument<String>("filePath")
                    if (filePath.isNullOrEmpty()) {
                        result.error("INVALID_PATH", "Ruta de archivo no proporcionada", null)
                        return@setMethodCallHandler
                    }

                    val sourceFile = File(filePath)
                    if (!sourceFile.exists()) {
                        result.error("FILE_NOT_FOUND", "El archivo APK no existe en $filePath", null)
                        return@setMethodCallHandler
                    }

                    // En Android 8.0+ verificar permiso de instalación de fuentes desconocidas
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        if (!packageManager.canRequestPackageInstalls()) {
                            val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                                data = Uri.parse("package:$packageName")
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            startActivity(intent)
                            result.success("PERMISSION_REQUIRED")
                            return@setMethodCallHandler
                        }
                    }

                    try {
                        // Garantizar que el APK se encuentre en una ruta cubierta por FileProvider (cacheDir)
                        val targetApk = if (sourceFile.canonicalPath.startsWith(cacheDir.canonicalPath)) {
                            sourceFile
                        } else {
                            val dest = File(cacheDir, "securedeck_install.apk")
                            sourceFile.copyTo(dest, overwrite = true)
                            dest
                        }

                        val contentUri: Uri = FileProvider.getUriForFile(
                            this,
                            "$packageName.fileprovider",
                            targetApk
                        )

                        val installIntent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(contentUri, "application/vnd.android.package-archive")
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        startActivity(installIntent)
                        result.success("INSTALL_STARTED")
                    } catch (e: Exception) {
                        result.error("INSTALL_ERROR", "Error al abrir el instalador: ${e.message}", null)
                    }
                }
                else -> result.notImplemented()
            }
        }

        // 2. Canal de control de micrófono (permisos y estado)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, MIC_METHOD_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "hasPermission" -> {
                    val granted = ContextCompat.checkSelfPermission(
                        this,
                        Manifest.permission.RECORD_AUDIO
                    ) == PackageManager.PERMISSION_GRANTED
                    result.success(granted)
                }
                "requestPermission" -> {
                    ActivityCompat.requestPermissions(
                        this,
                        arrayOf(Manifest.permission.RECORD_AUDIO),
                        RECORD_AUDIO_REQ_CODE
                    )
                    result.success(true)
                }
                "startMic" -> {
                    startRecording()
                    result.success(isRecording)
                }
                "stopMic" -> {
                    stopRecording()
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }

        // 3. Canal de eventos de audio en tiempo real (PCM 16-bit Mono @ 16kHz)
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, MIC_EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    micEventSink = events
                    startRecording()
                }

                override fun onCancel(arguments: Any?) {
                    stopRecording()
                    micEventSink = null
                }
            }
        )
    }

    @Synchronized
    private fun startRecording() {
        if (isRecording) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        val sampleRate = 16000
        val channelConfig = AudioFormat.CHANNEL_IN_MONO
        val audioFormat = AudioFormat.ENCODING_PCM_16BIT
        val minBufferSize = AudioRecord.getMinBufferSize(sampleRate, channelConfig, audioFormat)
        val bufferSize = maxOf(minBufferSize, 3200)

        try {
            val record = AudioRecord(
                MediaRecorder.AudioSource.MIC,
                sampleRate,
                channelConfig,
                audioFormat,
                bufferSize
            )

            if (record.state != AudioRecord.STATE_INITIALIZED) {
                record.release()
                return
            }

            audioRecord = record
            isRecording = true
            record.startRecording()

            recordingThread = Thread {
                // Fragmentos de ~100ms (1600 muestras * 2 bytes = 3200 bytes)
                val buffer = ByteArray(3200)
                while (isRecording) {
                    val read = record.read(buffer, 0, buffer.size)
                    if (read > 0) {
                        val base64Chunk = Base64.encodeToString(buffer, 0, read, Base64.NO_WRAP)
                        runOnUiThread {
                            micEventSink?.success(base64Chunk)
                        }
                    }
                }
            }.apply {
                name = "SecureDeck-MicThread"
                isDaemon = true
                start()
            }
        } catch (e: Exception) {
            stopRecording()
        }
    }

    @Synchronized
    private fun stopRecording() {
        isRecording = false
        try {
            audioRecord?.stop()
            audioRecord?.release()
        } catch (_: Exception) {
        } finally {
            audioRecord = null
            recordingThread = null
        }
    }

    override fun onDestroy() {
        stopRecording()
        super.onDestroy()
    }
}
