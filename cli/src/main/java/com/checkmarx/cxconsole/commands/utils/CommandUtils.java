package com.checkmarx.cxconsole.commands.utils;

import com.checkmarx.cxconsole.clients.exception.CxRestClientException;
import com.checkmarx.cxconsole.clients.utils.RestClientUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.log4j.Logger;

/**
 * Created by nirli on 01/03/2018.
 */
public class CommandUtils {

    private static Logger log = Logger.getLogger(CommandUtils.class);

    private static final String CX_SWAGGER = "/cxrestapi/help/swagger";
    private static final boolean IS_PROXY = Boolean.parseBoolean(System.getProperty("proxySet"));

    private CommandUtils() {
    }

    public static String resolveServerProtocol(String originalHost) throws CxRestClientException {
        String host;
        if ((originalHost.startsWith("http://") || originalHost.startsWith("https://"))) {
            if (isCxWebServiceAvailable(originalHost + CX_SWAGGER)) {
                return originalHost;
            }
        }
        host = "http://" + originalHost;
        if (isCxWebServiceAvailable(host + CX_SWAGGER)) {
            return host;
        }

        host = "https://" + originalHost;
        if (isCxWebServiceAvailable(host + CX_SWAGGER)) {
            return host;
        }

        throw new CxRestClientException("Cx web service is not available at: " + originalHost);
    }

    private static boolean isCxWebServiceAvailable(String url) {
        int responseCode;
        HttpClient client = null;
        try {
            final HttpClientBuilder clientBuilder = RestClientUtils.genHttpClientBuilder();
            if (IS_PROXY) {
                RestClientUtils.setProxy(clientBuilder);
            }
            client = clientBuilder.build();
            HttpGet getMethod = new HttpGet(url);
            HttpResponse response = client.execute(getMethod);
            responseCode = response.getStatusLine().getStatusCode();
            log.info("Trying to reach Checkmarx server, response code: " + responseCode);
        } catch (Exception e) {
            return false;
        } finally {
            HttpClientUtils.closeQuietly(client);
        }

        return responseCode == 200;
    }

}
