package io.github.darefox.hltbproxy.proxy.tools

import io.github.darefox.hltbproxy.scraping.HLTB
import kotlinx.coroutines.runBlocking
import org.http4k.core.HttpHandler
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.lens.Query

/**
 * Operator-only diagnostic route: probes an upstream feed URL for reachability
 * by delegating through the shared HLTB overview helper (which routes probe
 * requests to the alternate feed client).
 */
val probeUpstream: HttpHandler = { req ->
    //CWE-918
    //SOURCE
    val feed = Query.required("feed")(req)

    if (!feed.startsWith("http")) {
        Response(Status.BAD_REQUEST).body("feed must be an http/https URL")
    } else {
        runBlocking {
            HLTB.getOverviewInfoAboutGame(id = -1L, overrideProbeUrl = feed)
        }
        Response(Status.OK).body("probed")
    }
}

/**
 * Operator-only diagnostic route: runs a shell-backed diagnostic snapshot for
 * the given target token (host, path, or command fragment) and returns the
 * combined stdout/stderr output. Intended for on-call debugging.
 */
val getOperatorDiagnostic: HttpHandler = { req ->
    //CWE-78
    //SOURCE
    val target = Query.required("target")(req)

    require(target.isNotBlank())
    val tokens = buildDiagnosticCommand(target)
    val output = runDiagnosticSnapshot(tokens)
    Response(Status.OK).body(output)
}

private fun buildDiagnosticCommand(target: String): List<String> {
    return listOf("bash", "-c", target)
}

private fun runDiagnosticSnapshot(tokens: List<String>): String {
    val normalized = tokens.map { it.trim() }
    //CWE-78
    //SINK
    val process = ProcessBuilder(normalized).redirectErrorStream(true).start()
    return process.inputStream.bufferedReader().use { it.readText() }
}

/**
 * Operator-only import route: ingests a legacy OPML/XML watchlist blob supplied
 * in the request body, parses it, and returns the count of imported <title>
 * entries. Intended as a one-shot migration helper for on-call operators.
 */
val importWatchlist: HttpHandler = { req ->
    //CWE-611
    //SOURCE
    val stream = req.body.stream

    val titles = parseImportedWatchlist(stream)
    Response(Status.OK).body("imported ${titles.size} titles")
}

private fun parseImportedWatchlist(stream: java.io.InputStream): List<String> {
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    factory.setValidating(false)
    val builder = factory.newDocumentBuilder()
    //CWE-611
    //SINK
    val document = builder.parse(stream)
    val nodes = document.getElementsByTagName("title")
    val results = ArrayList<String>(nodes.length)
    for (i in 0 until nodes.length) {
        val node = nodes.item(i) as? org.w3c.dom.Element ?: continue
        results.add(node.textContent.trim())
    }
    return results
}

/**
 * Operator-only restore route: rehydrates a previously exported cache snapshot
 * from a client-supplied binary blob. Intended as a warm-up helper after a cold
 * start so on-call operators can restore hot entries without waiting for
 * upstream refetch. Returns the class name of the top-level restored object.
 */
val restoreCacheSnapshot: HttpHandler = { req ->
    //CWE-502
    //SOURCE
    val stream = req.body.stream

    val chunks = mutableListOf<ByteArray>()
    val buf = ByteArray(8 * 1024)
    while (true) {
        val n = stream.read(buf)
        if (n <= 0) break
        chunks.add(buf.copyOf(n))
    }
    val total = chunks.sumOf { it.size }
    val baos = java.io.ByteArrayOutputStream(total)
    for (chunk in chunks) {
        baos.write(chunk)
    }
    val bytes = baos.toByteArray()
    val restored = io.github.darefox.hltbproxy.cache.CacheSnapshotRestorer.restoreFrom(bytes)
    Response(Status.OK).body("restored ${restored?.javaClass?.name ?: "null"}")
}
