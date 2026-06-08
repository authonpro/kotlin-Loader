package pro.authon.sdk

fun main() {
    val auth = Authon("your-app-id", "your-api-key")

    // Connect
    if (!auth.init()) {
        println("[-] Failed to connect")
        return
    }
    println("[+] Connected: ${auth.appName} v${auth.appVersion}")

    // Auth
    println("\n[1] Login\n[2] License Key")
    print("\n> ")
    val choice = readlnOrNull()?.trim()

    val result = if (choice == "1") {
        print("Username: "); val u = readlnOrNull()?.trim() ?: ""
        print("Password: "); val p = readlnOrNull()?.trim() ?: ""
        auth.login(u, p)
    } else {
        print("License Key: "); val k = readlnOrNull()?.trim() ?: ""
        auth.license(k)
    }

    if (result["success"] != true) {
        println("\n[-] ${result["message"]}")
        return
    }

    println("\n[+] Authenticated!")
    println("    Level: ${auth.level}")
    println("    Subscription: ${auth.subscription ?: "None"}")
    println("    Expires: ${auth.expiresAt ?: "Lifetime"}")

    val msg = auth.getVar("welcome_message")
    if (msg != null) println("\n[*] $msg")

    auth.log("Kotlin SDK example executed")
    println("\n[+] Done. Logging out...")
    auth.logout()
}
