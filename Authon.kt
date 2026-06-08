/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║  Authon Kotlin SDK — Software Licensing & Authentication                   ║
 * ║  Version: 1.0.0                                                            ║
 * ║  No external dependencies (java.net.http, JDK 11+)                         ║
 * ║                                                                            ║
 * ║  Website: https://authon.pro                                               ║
 * ║  Docs:    https://authon.pro/docs                                          ║
 * ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
 * ║  Status:  https://authon.pro/status                                        ║
 * ║  Health:  https://api.authon.pro/health                                    ║
 * ║  GitHub:  https://github.com/authonpro                                     ║
 * ║                                                                            ║
 * ║  Usage:                                                                    ║
 * ║    val auth = Authon("app-id", "api-key")                                  ║
 * ║    auth.init()                                                             ║
 * ║    val result = auth.login("user", "pass")                                 ║
 * ║    if (result.success) println("Welcome ${auth.username}!")                 ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

package pro.authon.sdk

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration

/**
 * Authon SDK Client for Kotlin.
 *
 * Provides full authentication, licensing, variable storage,
 * file management, and activity logging capabilities.
 *
 * @param appId  Your Application ID from the Authon dashboard.
 * @param apiKey Your API Key from the Authon dashboard.
 * @param apiUrl Custom API URL (defaults to https://api.authon.pro/v1).
 */
class Authon(
    private val appId: String,
    private val apiKey: String,
    private val apiUrl: String = DEFAULT_API_URL
) {
    companion object {
        /** SDK version string. */
        const val VERSION = "1.0.0"

        /** Default API endpoint URL. */
        const val DEFAULT_API_URL = "https://api.authon.pro/v1"

        /** Default HTTP timeout in seconds. */
        const val DEFAULT_TIMEOUT = 15L

        /**
         * Generates a hardware ID unique to the current machine.
         *
         * Windows: Uses disk serial + computer name.
         * Linux:   Uses /etc/machine-id.
         * macOS:   Uses system_profiler hardware UUID.
         *
         * @return 32-character lowercase hex MD5 hash.
         */
        @JvmStatic
        fun getHWID(): String {
            val raw = try {
                val os = System.getProperty("os.name", "").lowercase()
                when {
                    "win" in os -> {
                        val process = Runtime.getRuntime().exec("wmic diskdrive get serialnumber")
                        val reader = BufferedReader(InputStreamReader(process.inputStream))
                        reader.readLine() // skip header
                        val serial = reader.readLine()?.trim() ?: ""
                        reader.close()
                        process.waitFor()
                        val computerName = System.getenv("COMPUTERNAME") ?: ""
                        serial + computerName
                    }
                    "mac" in os -> {
                        val process = Runtime.getRuntime().exec("system_profiler SPHardwareDataType")
                        val reader = BufferedReader(InputStreamReader(process.inputStream))
                        var uuid = ""
                        reader.forEachLine { line ->
                            if ("UUID" in line) {
                                uuid = line.split(":").getOrNull(1)?.trim() ?: ""
                                return@forEachLine
                            }
                        }
                        reader.close()
                        process.waitFor()
                        uuid.ifEmpty { System.getProperty("user.name") + System.getProperty("os.arch") }
                    }
                    else -> {
                        val machineId = File("/etc/machine-id")
                        if (machineId.exists()) {
                            machineId.readText().trim()
                        } else {
                            System.getProperty("user.name") + System.getProperty("os.arch")
                        }
                    }
                }
            } catch (e: Exception) {
                System.getProperty("user.name", "user") + System.getProperty("os.arch", "x64")
            }

            return md5(raw.ifEmpty { "fallback-${System.getProperty("user.name")}" })
        }

        /** Computes MD5 hash of a string. */
        private fun md5(input: String): String {
            val md = MessageDigest.getInstance("MD5")
            val hash = md.digest(input.toByteArray(StandardCharsets.UTF_8))
            return hash.joinToString("") { "%02x".format(it) }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SESSION STATE
    // ═══════════════════════════════════════════════════════════════════════════

    /** Current session token. Null if not authenticated. */
    var sessionToken: String? = null
        private set

    /** Authenticated username. Null if not authenticated. */
    var username: String? = null
        private set

    /** User's access level (0+). */
    var level: Int = 0
        private set

    /** Subscription plan name. Null if not set. */
    var subscription: String? = null
        private set

    /** Subscription expiration date (ISO 8601). Null for lifetime. */
    var expiresAt: String? = null
        private set

    // ═══════════════════════════════════════════════════════════════════════════
    // APP INFO
    // ═══════════════════════════════════════════════════════════════════════════

    /** Application name (set after init). */
    var appName: String? = null
        private set

    /** Application version (set after init). */
    var appVersion: String? = null
        private set

    /** Whether HWID locking is enabled. */
    var hwidLock: Boolean = false
        private set

    /** Whether hash checking is enabled. */
    var hashCheck: Boolean = false
        private set

    /** Whether init() has been called successfully. */
    var initialized: Boolean = false
        private set

    /** Whether the client has an active session. */
    val isAuthenticated: Boolean
        get() = !sessionToken.isNullOrEmpty()

    private val httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(DEFAULT_TIMEOUT))
        .build()

    init {
        require(appId.isNotBlank()) { "appId is required" }
        require(apiKey.isNotBlank()) { "apiKey is required" }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Initializes the connection to the Authon API.
     * Must be called before any other API method.
     *
     * @return AuthonResponse with app info on success.
     */
    fun init(): AuthonResponse {
        val resp = request(mapOf("type" to "init"))
        if (resp.success) {
            appName = resp.getString("name")
            appVersion = resp.getString("version")
            hwidLock = resp.getBoolean("hwidLock")
            hashCheck = resp.getBoolean("hashCheck")
            initialized = true
        }
        return resp
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AUTHENTICATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Authenticates with username and password.
     *
     * @param username User's username.
     * @param password User's password.
     * @param hwid     Hardware ID (null to auto-generate).
     * @return AuthonResponse. On success, session state is populated.
     *
     * Possible error messages:
     * - "Invalid credentials"
     * - "Account banned"
     * - "Hardware ID mismatch"
     * - "Subscription expired"
     * - "Account is frozen"
     * - "VPN/Proxy connections are not allowed"
     */
    fun login(username: String, password: String, hwid: String? = null): AuthonResponse {
        if (username.isBlank() || password.isBlank()) {
            return AuthonResponse.error("Username and password are required")
        }

        val resp = request(mapOf(
            "type" to "login",
            "username" to username,
            "password" to password,
            "hwid" to (hwid?.takeIf { it.isNotBlank() } ?: getHWID())
        ))

        if (resp.success) extractSession(resp)
        return resp
    }

    /**
     * Authenticates using a license key only.
     *
     * @param licenseKey The license key to validate/activate.
     * @param hwid       Hardware ID (null to auto-generate).
     * @return AuthonResponse. Possible errors: "Invalid or already used license key"
     */
    fun license(licenseKey: String, hwid: String? = null): AuthonResponse {
        if (licenseKey.isBlank()) return AuthonResponse.error("License key is required")

        val resp = request(mapOf(
            "type" to "license",
            "licenseKey" to licenseKey,
            "hwid" to (hwid?.takeIf { it.isNotBlank() } ?: getHWID())
        ))

        if (resp.success) extractSession(resp)
        return resp
    }

    /**
     * Registers a new user account with a license key.
     *
     * @param username   Desired username.
     * @param password   Desired password.
     * @param licenseKey A valid, unused license key.
     * @param hwid       Hardware ID (null to auto-generate).
     * @return AuthonResponse. Possible errors: "Username already exists"
     */
    fun register(username: String, password: String, licenseKey: String, hwid: String? = null): AuthonResponse {
        if (username.isBlank() || password.isBlank() || licenseKey.isBlank()) {
            return AuthonResponse.error("Username, password, and licenseKey are required")
        }

        return request(mapOf(
            "type" to "register",
            "username" to username,
            "password" to password,
            "licenseKey" to licenseKey,
            "hwid" to (hwid?.takeIf { it.isNotBlank() } ?: getHWID())
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SESSION MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Validates the current session (heartbeat).
     *
     * @return true if the session is still valid.
     */
    fun check(): Boolean {
        val token = sessionToken ?: return false
        val resp = request(mapOf("type" to "check", "sessionToken" to token))
        return resp.success
    }

    /**
     * Ends the current session and clears local state.
     *
     * @return true if logout was successful.
     */
    fun logout(): Boolean {
        val token = sessionToken ?: return false
        val resp = request(mapOf("type" to "logout", "sessionToken" to token))
        if (resp.success) {
            sessionToken = null
            username = null
            level = 0
            subscription = null
            expiresAt = null
        }
        return resp.success
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VARIABLES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Gets an application-level variable (shared across all users).
     *
     * @param key Variable name.
     * @return Variable value, or null if not found.
     */
    fun getVar(key: String): String? {
        val resp = request(mapOf(
            "type" to "var",
            "key" to key,
            "sessionToken" to (sessionToken ?: "")
        ))
        return if (resp.success) resp.getString("value") else null
    }

    /**
     * Sets a user-level variable (stored per authenticated user).
     *
     * @param key   Variable name.
     * @param value Variable value.
     * @return true if saved successfully.
     */
    fun setVar(key: String, value: String): Boolean {
        val resp = request(mapOf(
            "type" to "setvar",
            "key" to key,
            "value" to value,
            "sessionToken" to (sessionToken ?: "")
        ))
        return resp.success
    }

    /**
     * Gets a user-level variable.
     *
     * @param key Variable name.
     * @return Variable value, or null if not found.
     */
    fun getUserVar(key: String): String? {
        val resp = request(mapOf(
            "type" to "getvar",
            "key" to key,
            "sessionToken" to (sessionToken ?: "")
        ))
        return if (resp.success) resp.getString("value") else null
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FILES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Lists all files available to the authenticated user.
     *
     * @return AuthonResponse with data array containing file entries.
     */
    fun listFiles(): AuthonResponse {
        return request(mapOf(
            "type" to "list_files",
            "sessionToken" to (sessionToken ?: "")
        ))
    }

    /**
     * Downloads a file by its ID and returns raw bytes.
     *
     * @param fileId File ID from listFiles().
     * @return File content as ByteArray, or null on failure.
     */
    fun downloadFile(fileId: String): ByteArray? {
        val token = sessionToken ?: return null
        if (fileId.isBlank()) return null

        return try {
            val json = buildJson(mapOf(
                "type" to "file",
                "appId" to appId,
                "apiKey" to apiKey,
                "fileId" to fileId,
                "sessionToken" to token
            ))

            val req = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", "application/json")
                .header("User-Agent", "Authon-Kotlin-SDK/$VERSION")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build()

            val resp = httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray())
            val contentType = resp.headers().firstValue("content-type").orElse("")

            if ("octet-stream" in contentType) {
                resp.body()
            } else {
                // Try GET fallback
                val getUrl = "$apiUrl/files/download/$fileId?token=$token"
                val getReq = HttpRequest.newBuilder()
                    .uri(URI.create(getUrl))
                    .timeout(Duration.ofSeconds(60))
                    .GET()
                    .build()
                val getResp = httpClient.send(getReq, HttpResponse.BodyHandlers.ofByteArray())
                val getCt = getResp.headers().firstValue("content-type").orElse("")
                if ("octet-stream" in getCt) getResp.body() else null
            }
        } catch (e: Exception) {
            null
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOGGING & ANALYTICS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Sends an activity log message to the dashboard.
     *
     * @param message Log message (max 500 chars).
     * @return true if logged successfully.
     */
    fun log(message: String): Boolean {
        val resp = request(mapOf(
            "type" to "log",
            "message" to message.take(500),
            "sessionToken" to (sessionToken ?: "")
        ))
        return resp.success
    }

    /**
     * Gets the list of currently online users.
     *
     * @return AuthonResponse with data containing count and users.
     */
    fun fetchOnline(): AuthonResponse {
        return request(mapOf(
            "type" to "fetch_online",
            "sessionToken" to (sessionToken ?: "")
        ))
    }

    /**
     * Gets application statistics.
     *
     * @return AuthonResponse with data containing totalUsers, onlineUsers, totalKeys, appVersion.
     */
    fun fetchStats(): AuthonResponse {
        return request(mapOf(
            "type" to "fetch_stats",
            "sessionToken" to (sessionToken ?: "")
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Checks if an IP or HWID is blacklisted.
     *
     * @param ip   IP address to check (null to skip).
     * @param hwid HWID to check (null to skip).
     * @return AuthonResponse with blacklisted and reason.
     */
    fun checkBlacklist(ip: String? = null, hwid: String? = null): AuthonResponse {
        val payload = mutableMapOf<String, String>("type" to "check_blacklist")
        ip?.takeIf { it.isNotBlank() }?.let { payload["ip"] = it }
        hwid?.takeIf { it.isNotBlank() }?.let { payload["hwid"] = it }
        return request(payload)
    }

    /**
     * Redeems a referral code for bonus subscription days.
     *
     * @param code Referral code.
     * @return AuthonResponse with expiresAt and rewardDays.
     */
    fun redeemReferral(code: String): AuthonResponse {
        return request(mapOf(
            "type" to "redeem_referral",
            "code" to code,
            "sessionToken" to (sessionToken ?: "")
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INTERNAL
    // ═══════════════════════════════════════════════════════════════════════════

    private fun request(payload: Map<String, String>): AuthonResponse {
        return try {
            val fullPayload = payload.toMutableMap()
            fullPayload["appId"] = appId
            fullPayload["apiKey"] = apiKey

            val json = buildJson(fullPayload)

            val req = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .timeout(Duration.ofSeconds(DEFAULT_TIMEOUT))
                .header("Content-Type", "application/json")
                .header("User-Agent", "Authon-Kotlin-SDK/$VERSION")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build()

            val resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString())
            AuthonResponse.parse(resp.body())
        } catch (e: java.net.ConnectException) {
            AuthonResponse.error("Connection failed. Check https://authon.pro/status")
        } catch (e: java.net.http.HttpTimeoutException) {
            AuthonResponse.error("Request timed out")
        } catch (e: Exception) {
            AuthonResponse.error("Unexpected error: ${e.message}")
        }
    }

    private fun extractSession(resp: AuthonResponse) {
        sessionToken = resp.getString("sessionToken")
        username = resp.getString("username")
        level = resp.getInt("level")
        subscription = resp.getString("subscription")
        expiresAt = resp.getString("expiresAt")
    }

    private fun buildJson(map: Map<String, String>): String {
        val entries = map.entries.joinToString(",") { (k, v) ->
            "\"${jsonEscape(k)}\":\"${jsonEscape(v)}\""
        }
        return "{$entries}"
    }

    private fun jsonEscape(s: String): String {
        return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RESPONSE CLASS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Represents an API response from Authon.
     */
    data class AuthonResponse(
        val success: Boolean,
        val message: String? = null,
        val data: Map<String, Any?> = emptyMap(),
        val rawBody: String = ""
    ) {
        /** Get a string value from the response data. */
        fun getString(key: String): String? = data[key]?.toString()

        /** Get an int value from the response data. */
        fun getInt(key: String): Int = when (val v = data[key]) {
            is Number -> v.toInt()
            is String -> v.toIntOrNull() ?: 0
            else -> 0
        }

        /** Get a boolean value from the response data. */
        fun getBoolean(key: String): Boolean = when (val v = data[key]) {
            is Boolean -> v
            is String -> v.toBoolean()
            else -> false
        }

        companion object {
            /** Create an error response locally. */
            fun error(message: String) = AuthonResponse(success = false, message = message)

            /** Parse a JSON response string. */
            fun parse(body: String): AuthonResponse {
                return try {
                    val map = parseJsonObject(body)
                    val success = map["success"] == true || map["success"] == "true"
                    val message = map["message"]?.toString()
                    @Suppress("UNCHECKED_CAST")
                    val data = (map["data"] as? Map<String, Any?>) ?: emptyMap()
                    AuthonResponse(success, message, data, body)
                } catch (e: Exception) {
                    AuthonResponse(false, "Failed to parse response", rawBody = body)
                }
            }

            /** Minimal JSON object parser. */
            @Suppress("UNCHECKED_CAST")
            private fun parseJsonObject(json: String): Map<String, Any?> {
                val trimmed = json.trim()
                if (!trimmed.startsWith("{")) return emptyMap()

                val map = mutableMapOf<String, Any?>()
                var i = 1
                while (i < trimmed.length) {
                    while (i < trimmed.length && trimmed[i].isWhitespace()) i++
                    if (i >= trimmed.length || trimmed[i] == '}') break
                    if (trimmed[i] == ',') { i++; continue }

                    // Key
                    if (trimmed[i] != '"') { i++; continue }
                    val keyStart = i + 1
                    val keyEnd = trimmed.indexOf('"', keyStart)
                    if (keyEnd == -1) break
                    val key = trimmed.substring(keyStart, keyEnd)
                    i = keyEnd + 1

                    // Colon
                    while (i < trimmed.length && trimmed[i] != ':') i++
                    i++
                    while (i < trimmed.length && trimmed[i].isWhitespace()) i++
                    if (i >= trimmed.length) break

                    // Value
                    when {
                        trimmed[i] == '"' -> {
                            val valStart = i + 1
                            var valEnd = valStart
                            while (valEnd < trimmed.length) {
                                if (trimmed[valEnd] == '\\') { valEnd += 2; continue }
                                if (trimmed[valEnd] == '"') break
                                valEnd++
                            }
                            map[key] = trimmed.substring(valStart, valEnd)
                                .replace("\\\"", "\"").replace("\\\\", "\\")
                            i = valEnd + 1
                        }
                        trimmed[i] == '{' -> {
                            var depth = 1; val start = i; i++
                            while (i < trimmed.length && depth > 0) {
                                if (trimmed[i] == '{') depth++
                                else if (trimmed[i] == '}') depth--
                                i++
                            }
                            map[key] = parseJsonObject(trimmed.substring(start, i))
                        }
                        trimmed[i] == '[' -> {
                            var depth = 1; val start = i; i++
                            while (i < trimmed.length && depth > 0) {
                                if (trimmed[i] == '[') depth++
                                else if (trimmed[i] == ']') depth--
                                i++
                            }
                            map[key] = trimmed.substring(start, i) // raw array string
                        }
                        trimmed.startsWith("true", i) -> { map[key] = true; i += 4 }
                        trimmed.startsWith("false", i) -> { map[key] = false; i += 5 }
                        trimmed.startsWith("null", i) -> { map[key] = null; i += 4 }
                        else -> {
                            val numStart = i
                            while (i < trimmed.length && trimmed[i] !in ",}] \t\r\n") i++
                            val numStr = trimmed.substring(numStart, i)
                            map[key] = numStr.toIntOrNull() ?: numStr.toDoubleOrNull() ?: numStr
                        }
                    }
                }
                return map
            }
        }
    }
}
