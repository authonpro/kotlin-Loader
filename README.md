# Authon Kotlin SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Kotlin SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/jMZCTKPsmE">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- Kotlin 1.8+ / JVM 11+
- No external dependencies (uses java.net.http)

Works with: **Android**, **Minecraft Plugins (Paper/Spigot)**, **Desktop (Compose)**

## Installation

Copy `Authon.kt` into your project.

## Quick Start

```kotlin
val auth = Authon("your-app-id", "your-api-key")
auth.init()

val result = auth.login("username", "password")
if (result["success"] == true) {
    println("Level: ${auth.level}")
}
auth.logout()
```

## Run Example

```bash
kotlinc Authon.kt Example.kt -include-runtime -d app.jar
java -jar app.jar
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/jMZCTKPsmE
- 📊 Status: https://authon.pro/status
- 🔗 API Health: https://api.authon.pro/health

## License

MIT
