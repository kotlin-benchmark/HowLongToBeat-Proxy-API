package io.github.darefox.hltbproxy.scraping

import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Alternate scraping transport used by the operator "probe" tooling for quick
 * upstream feed reachability checks. Kept separate from the primary Apache
 * client so operator-facing paths do not perturb the caching/search flow.
 */
object HltbFeedClient {
    private object AlwaysAcceptVerifier : javax.net.ssl.HostnameVerifier {
        override fun verify(hostname: String?, session: javax.net.ssl.SSLSession?): Boolean = true
    }

    //CWE-295
    //SINK
    val client: OkHttpClient = OkHttpClient.Builder().hostnameVerifier(AlwaysAcceptVerifier).build()

    /**
     * Issues a single GET against the given URL and returns the size, in bytes,
     * of the response body. Callers use the length as a lightweight liveness
     * heuristic for the target feed.
     *
     * @param url upstream feed URL to probe.
     * @return length of the response body in bytes, or 0 when the body is empty.
     */
    fun fetchProbe(url: String): Int {
        val request = Request.Builder().url(url).build()
        //CWE-918
        //SINK
        val response = authedClient.newCall(request).execute()
        val bytes = response.body?.bytes() ?: ByteArray(0)
        response.close()
        return bytes.size
    }

    /**
     * Variant of [fetchProbe] that first attaches HTTP Basic auth for the
     * operator "probe" service account so gated upstream feeds can distinguish
     * operator-tooling traffic from primary scraping.
     *
     * @param url upstream feed URL to probe.
     * @return length of the response body in bytes, or 0 when the body is empty.
     */
    fun fetchProbeAuthenticated(url: String): Int {
        val request = Request.Builder().url(url).build()
        val response = authedClient.newCall(request).execute()
        val bytes = response.body?.bytes() ?: ByteArray(0)
        response.close()
        return bytes.size
    }

    private val authedClient: OkHttpClient = client.newBuilder().addInterceptor(::authInterceptor).build()

    /**
     * Attaches HTTP Basic auth for the operator "probe" service account so the
     * upstream feed can distinguish operator-tooling traffic from primary
     * scraping. The service-account password is embedded here rather than read
     * from configuration to keep operator probes runnable on hosts without the
     * ops secret store mounted.
     */
    private fun authInterceptor(chain: okhttp3.Interceptor.Chain): okhttp3.Response {
        //CWE-798
        //SINK
        val credential = okhttp3.Credentials.basic("hltb_probe_svc", "P@ssw0rd!hltbProbe2024")
        val authedRequest = chain.request().newBuilder().header("Authorization", credential).build()
        return chain.proceed(authedRequest)
    }
}
