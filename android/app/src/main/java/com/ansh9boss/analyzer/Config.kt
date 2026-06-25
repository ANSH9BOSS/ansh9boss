package com.ansh9boss.analyzer

object Config {
    const val VERSION = "1.0.0"
    const val DEFAULT_API_URL = "https://ansh9boss.vercel.app"

    var knownCheats = listOf(
        "wurst", "meteor", "sigma", "impact", "aristois", "future", "liquidbounce",
        "wolfram", "inertia", "ares", "sentry", "entropy", "reflex", "bleach",
        "ancientaura", "killaura", "huzuni", "nodus", "vape", "badlion", "mathax",
        "kamiblue", "kami", "salhack", "rusherhack"
    )

    var knownPackages = listOf(
        "meteorclient", "wurst", "sigma", "future", "liquidbounce", "mathax",
        "ares", "wolfram", "kamiblue", "salhack", "rusherhack", "aristois", "huzuni", "vape"
    )

    var cheatStrings = listOf(
        "aimbot", "killaura", "esp", "wallhack", "xray", "freecam",
        "nofall", "scaffold", "triggerbot", "autoclick", "baritone", "pathfind",
        "autototem", "fastplace", "criticals", "antiknockback", "nuker",
        "jesus", "automine", "cheatengine"
    )
}
