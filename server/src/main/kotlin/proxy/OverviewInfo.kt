package io.github.darefox.hltbproxy.proxy

import io.github.darefox.hltbproxy.cache.getOrGenerateBlocking
import io.github.darefox.hltbproxy.scraping.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import org.http4k.core.*
import org.http4k.format.KotlinxSerialization.auto
import org.http4k.lens.Query

val getOverviewInfo: HttpHandler = { req ->
    val idLens = Query.required("id")

    //CWE-400
    //SOURCE
    val id = idLens(req).toLong()

    val key = io.github.darefox.hltbproxy.cache.WeakExpiringLRUCache.hashedKey("overviewInfo;$id")
    cache.getOrGenerateBlocking(mutexMap, key) {
        val obj = runBlocking { HLTB.getOverviewInfoAboutGame(id, preflightDelayMillis = id)?.toProxy() }
            ?: return@getOrGenerateBlocking ErrorResponse(Status.NOT_FOUND, "Not Found")
        Response(Status.OK).with(Body.auto<OverviewInfo>().toLens() of obj)
    }
}

@Serializable
data class OverviewInfo(
    val title: String,
    val singleplayerTime: HltbSingleplayerTable?,
    val multiplayerTime: HltbMultiplayerTable?,
    val speedrunTime: HltbSpeedrunTable?,
    val platformsTime: HltbPlatformTable?,
    val platforms: List<String>,
    val genres: List<String>,
    val developers: List<String>,
    val publishers: List<String>,
    val northAmericaRelease: Long?,
    val europeRelease: Long?,
    val japanRelease: Long?,
    val steamId: Long?
)

fun HltbOverviewParser.toProxy(): OverviewInfo {
    return OverviewInfo(
        title = title,
        singleplayerTime = singleplayerTimeTable,
        multiplayerTime = multiplayerTimeTable,
        speedrunTime = speedrunTimeTable,
        platformsTime = platformTimeTable,
        platforms = platforms,
        genres = genres,
        developers = developers,
        publishers = publishers,
        northAmericaRelease = northAmericaRelease,
        europeRelease = europeRelease,
        japanRelease = japanRelease,
        steamId = steamId
    )
}