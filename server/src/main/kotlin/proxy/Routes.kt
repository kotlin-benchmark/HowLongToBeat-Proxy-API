package io.github.darefox.hltbproxy.proxy

import io.github.darefox.hltbproxy.proxy.tools.getOperatorDiagnostic
import io.github.darefox.hltbproxy.proxy.tools.importWatchlist
import io.github.darefox.hltbproxy.proxy.tools.probeUpstream
import io.github.darefox.hltbproxy.proxy.tools.restoreCacheSnapshot
import org.http4k.core.Method.GET
import org.http4k.core.Method.POST
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.routing.bind
import org.http4k.routing.routes

val serverRoutes = routes(
    "/" bind GET to {
        Response(Status.TEMPORARY_REDIRECT)
            .header("Location", "https://github.com/DareFox/HowLongToBeat-Proxy-API")
    },
    "/v1/query" bind GET to queryGames,
    "/v1/overview" bind GET to getOverviewInfo,
    "/v1/cache" bind GET to cacheInfo,
    "/v1/tools/probe" bind GET to probeUpstream,
    "/v1/tools/diag" bind GET to getOperatorDiagnostic,
    "/v1/tools/import" bind POST to importWatchlist,
    "/v1/tools/restore" bind POST to restoreCacheSnapshot
).withFilter(corsAll)

