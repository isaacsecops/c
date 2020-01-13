package com.checkmarx.cxconsole.clients.utils;

import com.checkmarx.cxconsole.clients.arm.CxRestArmClient;
import com.checkmarx.cxconsole.clients.arm.dto.Policy;
import com.checkmarx.cxconsole.clients.arm.exceptions.CxRestARMClientException;
import com.checkmarx.cxconsole.clients.exception.CxRestClientException;
import com.checkmarx.cxconsole.clients.exception.CxValidateResponseException;
import com.checkmarx.cxconsole.clients.general.dto.CxProviders;
import com.checkmarx.cxconsole.clients.sast.dto.ScanSettingDTO;
import com.checkmarx.cxconsole.clients.sast.dto.ScanSettingDTODeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.type.CollectionType;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Consts;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.auth.DigestSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.ssl.SSLContexts;
import org.apache.log4j.Logger;
import org.json.JSONObject;

import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static com.checkmarx.cxconsole.exitcodes.Constants.ExitCodes.POLICY_VIOLATION_ERROR_EXIT_CODE;
import static com.checkmarx.cxconsole.exitcodes.Constants.ExitCodes.SCAN_SUCCEEDED_EXIT_CODE;

/**
 * Created by nirli on 20/02/2018.
 */
public class RestClientUtils {

    private static Logger log = Logger.getLogger(RestClientUtils.class);

    private static final String SEPARATOR = ",";

    private static String HTTP_HOST = System.getProperty("http.proxyHost");
    private static String HTTP_PORT = System.getProperty("http.proxyPort");
    private static String HTTP_USERNAME = System.getProperty("http.proxyUser");
    private static String HTTP_PASSWORD = System.getProperty("http.proxyPassword");

    private static String HTTPS_HOST = System.getProperty("https.proxyHost");
    private static String HTTPS_PORT = System.getProperty("https.proxyPort");
    private static String HTTPS_USERNAME = System.getProperty("https.proxyUser");
    private static String HTTPS_PASSWORD = System.getProperty("https.proxyPassword");

    private RestClientUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static JSONObject parseJsonObjectFromResponse(HttpResponse response) throws IOException {
        String responseInString = createStringFromResponse(response).toString();
        return new JSONObject(responseInString);
    }

    public static <ResponseObj> ResponseObj parseJsonFromResponse(HttpResponse response, Class<ResponseObj> dtoClass) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(createStringFromResponse(response).toString(), dtoClass);
    }

    public static <ResponseObj> List<ResponseObj> parseJsonListFromResponse(HttpResponse response, CollectionType dtoClass) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(createStringFromResponse(response).toString(), dtoClass);
    }

    public static <ResponseObj> ResponseObj parseFromURL(String url, Class<ResponseObj> dtoClass) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(fromUrlToJson(url), dtoClass);
    }

    private static StringBuilder createStringFromResponse(HttpResponse response) throws IOException {
        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), Consts.UTF_8));

        StringBuilder result = new StringBuilder();
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        return result;
    }

    public static ScanSettingDTO parseScanSettingResponse(HttpResponse response) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addDeserializer(ScanSettingDTO.class, new ScanSettingDTODeserializer());
        mapper.registerModule(module);

        return mapper.readValue(createStringFromResponse(response).toString(), ScanSettingDTO.class);
    }

    public static void validateClientResponse(HttpResponse response, int status, String message) throws CxValidateResponseException {
        try {
            if (response.getStatusLine().getStatusCode() != status) {
                String responseBody = IOUtils.toString(response.getEntity().getContent(), Charset.defaultCharset());
                if (responseBody.contains("<!DOCTYPE html PUBLIC \"")) {
                    responseBody = "No error message";
                }
                throw new CxValidateResponseException(message + ": " + "status code: " + response.getStatusLine().getStatusCode() + ". Error message:" + responseBody);
            }
        } catch (IOException e) {
            throw new CxValidateResponseException("Error parse REST response body: " + e.getMessage());
        }
    }

    public static void validateTokenResponse(HttpResponse response, int status, String message) throws CxValidateResponseException {
        try {
            if (response.getStatusLine().getStatusCode() != status) {
                String responseBody = IOUtils.toString(response.getEntity().getContent(), Charset.defaultCharset());
                responseBody = responseBody.replace("{", "").replace("}", "").replace(System.getProperty("line.separator"), " ").replace("  ", "");
                if (responseBody.contains("<!DOCTYPE html>")) {
                    throw new CxValidateResponseException(message + ": " + "status code: 500. Error message: Internal Server Error");
                } else if (responseBody.contains("\"error\":\"invalid_grant\"")) {
                    throw new CxValidateResponseException(message);
                } else {
                    throw new CxValidateResponseException(message + ": " + "status code: " + response.getStatusLine() + ". Error message:" + responseBody);
                }
            }
        } catch (IOException e) {
            throw new CxValidateResponseException("Error parse REST response body: " + e.getMessage());
        }
    }

    public static HttpClientBuilder genHttpClientBuilder() {
        try {
            return HttpClients.custom().setSSLSocketFactory(getSSLSF());
        } catch (CxRestClientException e) {
            log.error("[CX-CLI] Fail to set SSL context", e);
        }
        return HttpClients.custom();
    }

    public static void setClientProxy(HttpClientBuilder clientBuilder, String proxyHost, int proxyPort) throws CxRestClientException {
        log.debug(String.format("Setting proxy to %s:%s", proxyHost, proxyPort));
        HttpHost proxyObject = new HttpHost(proxyHost, proxyPort);
        clientBuilder
                .setProxy(proxyObject)
                .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy())
                .setSSLSocketFactory(getSSLSF());
    }

    public static void setProxy(HttpClientBuilder cb) {
        try {
            HttpHost proxy;
            if (!StringUtils.isEmpty(HTTPS_HOST) && !StringUtils.isEmpty(HTTPS_PORT)) {
                proxy = new HttpHost(HTTPS_HOST, Integer.parseInt(HTTPS_PORT), "https");
                cb.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
                if (!StringUtils.isEmpty(HTTPS_USERNAME) && !StringUtils.isEmpty(HTTPS_PASSWORD)) {
                    RestClientUtils.setClientProxy(cb, HTTPS_HOST, Integer.parseInt(HTTPS_PORT), HTTPS_USERNAME, HTTPS_PASSWORD, "https");
                } else {
                    RestClientUtils.setClientProxy(cb, HTTPS_HOST, Integer.parseInt(HTTPS_PORT));
                }
            } else if (!StringUtils.isEmpty(HTTP_HOST) && !StringUtils.isEmpty(HTTP_PORT)) {
                proxy = new HttpHost(HTTP_HOST, Integer.parseInt(HTTP_PORT), "http");
                cb.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
                if (!StringUtils.isEmpty(HTTP_USERNAME) && !StringUtils.isEmpty(HTTP_PASSWORD)) {
                    RestClientUtils.setClientProxy(cb, HTTP_HOST, Integer.parseInt(HTTP_PORT), HTTP_USERNAME, HTTP_PASSWORD, "http");
                } else {
                    RestClientUtils.setClientProxy(cb, HTTP_HOST, Integer.parseInt(HTTP_PORT));
                }
            } else {
                log.warn("No proxy was set: missing params.");
            }
        } catch (CxRestClientException ex) {
            log.error("[CX-CLI] Fail to set proxy", ex);
        }
    }

    public static void setClientProxy(HttpClientBuilder clientBuilder, String proxyHost, int proxyPort, String proxyUser, String proxyPassword, String scheme) throws CxRestClientException {
        log.debug(String.format("Setting proxy with credentials to %s:%s", proxyHost, proxyPort));
        HttpHost proxy = new HttpHost(proxyHost, proxyPort, scheme);
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(new AuthScope(proxyHost, proxyPort), new UsernamePasswordCredentials(proxyUser, proxyPassword));

        clientBuilder
                .setProxy(proxy)
                .setDefaultCredentialsProvider(credsProvider)
                .setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy())
                .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build())
                .setConnectionManager(getHttpConnManager())
                .setDefaultRequestConfig(genRequestConfig())
                .setDefaultAuthSchemeRegistry(getAuthSchemeProviderRegistry());
    }

    public static RequestConfig genRequestConfig() {
        RequestConfig.Builder rcb = RequestConfig.custom();
        rcb.setConnectTimeout(60 * 1000);
        rcb.setSocketTimeout(60 * 1000);

        if (!StringUtils.isEmpty(HTTPS_HOST) && !StringUtils.isEmpty(HTTPS_PORT)) {
            rcb.setProxy(new HttpHost(HTTPS_HOST, Integer.parseInt(HTTPS_PORT), "https"));
            return rcb.build();
        } else if (!StringUtils.isEmpty(HTTP_HOST) && !StringUtils.isEmpty(HTTP_PORT)) {
            rcb.setProxy(new HttpHost(HTTP_HOST, Integer.parseInt(HTTP_PORT), "http"));
            return rcb.build();
        }

        return rcb.build();
    }

    public static SSLConnectionSocketFactory getSSLSF() throws CxRestClientException {
        TrustStrategy acceptingTrustStrategy = new TrustAllStrategy();
        SSLContext sslContext;
        try {
            sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new CxRestClientException("Fail to set trust all certificate, 'SSLConnectionSocketFactory'", e);
        }
        return new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
    }

    public static HttpClientConnectionManager getHttpConnManager() throws CxRestClientException {
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", getSSLSF())
                .register("http", new PlainConnectionSocketFactory())
                .build();

        return new BasicHttpClientConnectionManager(socketFactoryRegistry);
    }

    public static Registry<AuthSchemeProvider> getAuthSchemeProviderRegistry() {
        return RegistryBuilder.<AuthSchemeProvider>create()
                .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                .register(AuthSchemes.DIGEST, new DigestSchemeFactory())
                .build();
    }

    //Common method to be called by SAST or OSA commands.
    public static int getArmViolationExitCode(CxRestArmClient armClient, CxProviders provider, int projectId, Logger log) throws CxRestARMClientException {
        List<String> violatedPolicies = new ArrayList<>();
        int exitCode = SCAN_SUCCEEDED_EXIT_CODE;
        List<Policy> policiesViolations = armClient.getProjectViolations(projectId, provider.name());
        for (Policy policy : policiesViolations) {
            violatedPolicies.add(policy.getPolicyName());
        }
        if (violatedPolicies.size() > 0) {
            exitCode = POLICY_VIOLATION_ERROR_EXIT_CODE;
            StringBuilder builder = new StringBuilder();
            for (String policy : violatedPolicies) {
                builder.append(policy);
                builder.append(SEPARATOR);
            }
            String commaSeperatedPolicies = builder.toString();
            //Remove last comma
            commaSeperatedPolicies = commaSeperatedPolicies.substring(0, commaSeperatedPolicies.length() - SEPARATOR.length());
            log.info("Policy status: Violated");
            log.info("Policy violations: " + violatedPolicies.size() + " - " + commaSeperatedPolicies);

        } else {
            log.info("Policy Status: Compliant");
        }
        return exitCode;
    }

    static String fromUrlToJson(String url) {
        url = url.replaceAll("=", "\":\"");
        url = url.replaceAll("&", "\",\"");
        return "{\"" + url + "\"}";
    }
}