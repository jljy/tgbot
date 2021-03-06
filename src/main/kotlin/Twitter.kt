/**
 * Created by l on 2016/10/4.
 */

import com.github.kittinunf.fuel.core.FuelError
import com.github.kittinunf.fuel.httpGet
import com.github.kittinunf.fuel.httpPost
import com.github.kittinunf.result.Result
import sun.net.www.protocol.http.AuthScheme
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.comparisons.compareBy
import kotlin.comparisons.then

/**
 * Created by l on 2016/10/4.
 */

fun main(args: Array<String>) {
    val head = listOf<Pair<String,String>>( Pair("oauth_token", a().ok));
    val body = listOf<Pair<String,String>>(Pair("status","."));


    a().oathreq("POST","https://api.twitter.com/1.1/statuses/update.json", head, body);
}

public class a() {
//
    val ck = "iAtYJ4HpUVfIUoNnif1DA";
    val cs = "172fOpzuZoYzNYaU3mMYvE8m8MEyLbztOdbrUolU";
    var s="";

    var ok = s.substringBefore("&").substringAfter("=").toString();
    var os = s.substringAfter("&").substringAfter("=").substringBefore("&").toString();


    private fun String.percentEncode() = java.net.URLEncoder.encode(this, "UTF8");


    private fun parametersString(parameters: List<Pair<String, String>>) =
            parameters
                    .map { it.first.percentEncode() to it.second.percentEncode() }
                    .sortedWith(compareBy<Pair<String, String>> { it.first }.then(compareBy { it.second }))
                    .joinToString("&") { "${it.first}=${it.second}" }


    fun signatureBaseString(header: List<Pair<String, String>>, method: String, baseUrl: String, parameters: List<Pair<String, String>>) =
            listOf(method, baseUrl, parametersString(header + parameters))
                    .map { it.percentEncode() }
                    .joinToString("&")



  public   fun oathreq(method: String,baseUrl: String, head: List<Pair<String, String>>, body: List<Pair<String, String>> ): Result<String, FuelError> {

        val second = Math.random().toString();
        val second1 = (Date().time / 1000).toString()
        var headerList = listOf<Pair<String, String>>(Pair("oauth_consumer_key", ck),
                Pair("oauth_nonce", second),
                Pair("oauth_timestamp", second1),
                Pair("oauth_signature_method", "HMAC-SHA1"),
                Pair("oauth_version", "1.0")
        );
        headerList = headerList + head

        var bodyList = listOf<Pair<String, String>>();
        bodyList += body;


        val signatureBaseString = signatureBaseString(bodyList, method, baseUrl, headerList)

        println(signatureBaseString)

        val hmacSha1 = signatureBaseString.hmacSha1(cs + "&" + os)

        println(hmacSha1);
        val tim = second1
        val obtainRequestTokenHeader = obtainRequestTokenHeader(ck, second, hmacSha1, tim);
        println(obtainRequestTokenHeader)

        val header1 = (baseUrl).httpPost(bodyList)
                .header(mapOf("Authorization" to obtainRequestTokenHeader))

        val (request, response, result) = header1.responseString()
        println(result);
        return result;

    }


    fun obtainRequestTokenHeader(
            consumerKey: String,
            nonce: String
            , sig: String, tim: String
    ): String {
        val sig2 = sig.percentEncode();
        var s = """OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature="%s", oauth_signature_method="HMAC-SHA1", oauth_timestamp="%s", oauth_token="%s", oauth_version="1.0"""".format(consumerKey, nonce, sig2, tim, ok)
        println("auth header:" + s);
        return s;
    }


    private fun String.hmacSha1(key: String): String {
        val keySpec = SecretKeySpec(key.toByteArray(), "HmacSHA1")
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(keySpec)
        return Base64.getEncoder().encodeToString(mac.doFinal(this.toByteArray()))
    }


}
