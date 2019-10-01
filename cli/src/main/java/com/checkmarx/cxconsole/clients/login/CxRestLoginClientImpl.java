package com.checkmarx.cxconsole.clients.login;

import com.checkmarx.cxconsole.clients.exception.CxValidateResponseException;
import com.checkmarx.cxconsole.clients.login.dto.RestGetAccessTokenDTO;
import com.checkmarx.cxconsole.clients.login.exceptions.CxRestLoginClientException;
import com.checkmarx.cxconsole.clients.login.utils.LoginResourceURIBuilder;
import com.checkmarx.cxconsole.clients.token.utils.TokenHttpEntityBuilder;
import com.checkmarx.cxconsole.clients.utils.RestClientUtils;
import com.google.common.base.Strings;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.auth.DigestSchemeFactory;
import org.apache.http.impl.auth.win.WindowsCredentialsProvider;
import org.apache.http.impl.auth.win.WindowsNTLMSchemeFactory;
import org.apache.http.impl.auth.win.WindowsNegotiateSchemeFactory;
import org.apache.http.impl.client.*;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by nirli on 24/10/2017.
 */
public class CxRestLoginClientImpl implements CxRestLoginClient {

    private static final String CX_COOKIE = "cxCookie";
    private static final String CSRF_TOKEN_HEADER = "CXCSRFToken";

    private static Logger log = Logger.getLogger(CxRestLoginClientImpl.class);

    private final String username;
    private final String password;
    private final String hostName;
    private final String token;
    private boolean isLoggedIn = false;

    private HttpClient client;
    private static List<Header> headers = new ArrayList<>();

    private static final Header CLI_ORIGIN_HEADER = new BasicHeader("cxOrigin", "cx-CLI");
    private static Header authHeader;

    private static final String SERVER_STACK_TRACE_ERROR_MESSAGE = "Failed to get access token: Fail to authenticate: status code: HTTP/1.1 400 Bad Request. error:\"error\":\"invalid_grant\"";
    private static final String FAIL_TO_VALIDATE_TOKEN_RESPONSE_ERROR = " User authentication failed";

    private static CookieStore cookieStore = new BasicCookieStore();
    private String cxCookie = null;
    private String csrfToken = null;

    private static final boolean IS_PROXY = Boolean.parseBoolean(System.getProperty("proxySet"));

    public CxRestLoginClientImpl(String hostname, String token) {
        this.hostName = hostname;
        this.token = token;
        this.username = null;
        this.password = null;

        headers.add(CLI_ORIGIN_HEADER);

        final HttpClientBuilder clientBuilder = HttpClients.custom();
        if (IS_PROXY) {
            RestClientUtils.setProxy(clientBuilder);
        }

        try {
            client = clientBuilder
                    .setDefaultHeaders(headers)
                    .useSystemProperties()
                    .build();

            getAccessTokenFromRefreshToken(token);
        } catch (CxRestLoginClientException e) {
            if (e.getMessage().contains(SERVER_STACK_TRACE_ERROR_MESSAGE)) {
                log.trace("Failed to login, due to: " + e.getMessage());
                log.error("Failed to login: User authentication failed");
            } else {
                log.error("Failed to login with token: " + e.getMessage());
            }
        }
    }

    public CxRestLoginClientImpl(String hostname, String username, String password) {
        this.hostName = hostname;
        this.username = username;
        this.password = password;
        this.token = null;

        final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
        if (IS_PROXY) {
            RestClientUtils.setClientProxy(clientBuilder, PROXY_HOST, Integer.parseInt(PROXY_PORT));
        }

        SSLContext sslContext = generateSSLContext(TLS_PROTOCOL, log);
        headers.add(CLI_ORIGIN_HEADER);

        final HttpClientBuilder clientBuilder = HttpClients.custom();
        if (IS_PROXY) {
            RestClientUtils.setProxy(clientBuilder);
        }

        client = clientBuilder
                .useSystemProperties()
                .setDefaultHeaders(headers)
                .build();
    }

    public CxRestLoginClientImpl(String hostname) {
        this.hostName = hostname;
        this.username = null;
        this.password = null;
        this.token = null;

        headers.add(CLI_ORIGIN_HEADER);
        final Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                .register(AuthSchemes.DIGEST, new DigestSchemeFactory())
                .register(AuthSchemes.NTLM, new WindowsNTLMSchemeFactory(null))
                .register(AuthSchemes.SPNEGO, new WindowsNegotiateSchemeFactory(null))
                .build();
        final CredentialsProvider credsProvider = new WindowsCredentialsProvider(new SystemDefaultCredentialsProvider());

        final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
        if (IS_PROXY) {
            RestClientUtils.setProxy(clientBuilder);
        }

        client = clientBuilder
                .useSystemProperties()
                .setDefaultCredentialsProvider(credsProvider)
                .setDefaultAuthSchemeRegistry(authSchemeRegistry)
                .setDefaultCookieStore(cookieStore)
                .setDefaultHeaders(headers)
                .build();
    }

    @Override
    public void credentialsLogin() throws CxRestLoginClientException {
        HttpUriRequest postRequest;
        HttpResponse loginResponse = null;
        try {
            postRequest = RequestBuilder.post()
                    .setUri(String.valueOf(LoginResourceURIBuilder.getAccessTokenURL(new URL(hostName))))
                    .setHeader(HTTP.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
                    .setEntity(SastHttpEntityBuilder.createGetAccessTokenFromCredentialsParamsEntity(username, password))
                    .build();
            loginResponse = client.execute(postRequest);

            RestClientUtils.validateTokenResponse(loginResponse, 200, FAIL_TO_VALIDATE_TOKEN_RESPONSE_ERROR);
            RestGetAccessTokenDTO jsonResponse = RestClientUtils.parseJsonFromResponse(loginResponse, RestGetAccessTokenDTO.class);

            headers.add(new BasicHeader("Authorization", "Bearer " + jsonResponse.getAccessToken()));
            client = HttpClientBuilder.create().setDefaultHeaders(headers).build();
            final HttpClientBuilder clientBuilder = HttpClientBuilder.create().setDefaultHeaders(headers);
            if (IS_PROXY) {
                RestClientUtils.setProxy(clientBuilder);
            }
            client = clientBuilder
                    .useSystemProperties()
                    .build();
            isLoggedIn = true;
        } catch (IOException | CxValidateResponseException e) {
            log.error("Fail to login with credentials: " + e.getMessage());
            throw new CxRestLoginClientException("Fail to login with credentials: " + e.getMessage());
        } finally {
            HttpClientUtils.closeQuietly(loginResponse);
        }
    }

    @Override
    public void tokenLogin() throws CxRestLoginClientException {
        if (headers.size() == 2) {
            final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
            if (IS_PROXY) {
                RestClientUtils.setClientProxy(clientBuilder, PROXY_HOST, Integer.parseInt(PROXY_PORT));
            }
            client = clientBuilder
                    .setDefaultHeaders(headers)
                    .useSystemProperties()
                    .build();
            isLoggedIn = true;
        } else {
            throw new CxRestLoginClientException("Login failed");
        }
    }

    @Override
    public void ssoLogin() throws CxRestLoginClientException {
        HttpUriRequest request;
        HttpResponse loginResponse = null;
        try {
            request = RequestBuilder.post()
                    .setUri(String.valueOf(LoginResourceURIBuilder.buildWindowsAuthenticationLoginURL(new URL(hostName))))
                    .setConfig(RequestConfig.DEFAULT)
                    .setEntity(new StringEntity(""))
                    .build();
            loginResponse = client.execute(request);

            RestClientUtils.validateClientResponse(loginResponse, 200, "Fail to authenticate");
        } catch (IOException | CxValidateResponseException e) {
            log.error("Fail to login with windows authentication: " + e.getMessage());
            throw new CxRestLoginClientException("Fail to login with windows authentication: " + e.getMessage());
        } finally {
            HttpClientUtils.closeQuietly(loginResponse);
        }

        for (Cookie cookie : cookieStore.getCookies()) {
            if (cookie.getName().equals(CSRF_TOKEN_HEADER)) {
                csrfToken = cookie.getValue();
            }
            if (cookie.getName().equals(CX_COOKIE)) {
                cxCookie = cookie.getValue();
            }
        }

        headers.add(new BasicHeader(CSRF_TOKEN_HEADER, csrfToken));
        headers.add(new BasicHeader("cookie", String.format("CXCSRFToken=%s; cxCookie=%s", csrfToken, cxCookie)));

        final HttpClientBuilder clientBuilder = HttpClients.custom();
        if (IS_PROXY) {
            RestClientUtils.setProxy(clientBuilder);
        }
        client = clientBuilder
                .useSystemProperties()
                .setDefaultHeaders(headers).build();
        isLoggedIn = true;
    }

    private String extractAuthTokenFromResponse(HttpResponse loginResponse) throws IOException, CxValidateResponseException {
        String redirectURL = loginResponse.getHeaders("Location")[0].getValue();
        if (!redirectURL.contains("access_token")) {
            throw new CxValidateResponseException("Failed retrieving access token from server");
        }
        final RestGetAccessTokenDTO accessTokenDTO = RestClientUtils.parseFromURL(redirectURL, RestGetAccessTokenDTO.class);
        return accessTokenDTO.getAccessToken();
    }

    private String retrieveCookies() {
        List<Cookie> cookieList = cookieStore.getCookies();
        String cookies = "";
        for (Cookie cookie : cookieList) {
            cookies += cookie.getName() + "=" + cookie.getValue() + ";";
        }

        return cookies;
    }

    private void getAccessTokenFromRefreshToken(String refreshToken) throws CxRestLoginClientException {
        HttpResponse getAccessTokenResponse = null;
        String accessToken;
        HttpUriRequest postRequest;

        try {
            postRequest = RequestBuilder.post()
                    .setUri(String.valueOf(LoginResourceURIBuilder.getAccessTokenURL(new URL(hostName))))
                    .setHeader(HTTP.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
                    .setEntity(SastHttpEntityBuilder.createGetAccessTokenFromRefreshTokenParamsEntity(refreshToken))
                    .build();
            getAccessTokenResponse = client.execute(postRequest);

            RestClientUtils.validateTokenResponse(getAccessTokenResponse, 200, FAIL_TO_VALIDATE_TOKEN_RESPONSE_ERROR);

            RestGetAccessTokenDTO jsonResponse = RestClientUtils.parseJsonFromResponse(getAccessTokenResponse, RestGetAccessTokenDTO.class);
            accessToken = jsonResponse.getAccessToken();
        } catch (IOException | CxValidateResponseException e) {
            log.trace("Failed to get access token: " + e.getMessage());
            throw new CxRestLoginClientException("User authentication failed");
        } finally {
            HttpClientUtils.closeQuietly(getAccessTokenResponse);
        }
        headers.add(new BasicHeader("Authorization", "Bearer " + accessToken));
    }

    @Override
    public HttpClient getClient() {
        return client;
    }

    @Override
    public String getHostName() {
        return hostName;
    }

    @Override
    public boolean isLoggedIn() {
        return isLoggedIn;
    }

    @Override
    public boolean isCredentialsLogin() {
        return !Strings.isNullOrEmpty(username) && !Strings.isNullOrEmpty(password);
    }

    @Override
    public boolean isTokenLogin() {
        return !Strings.isNullOrEmpty(token);
    }

    @Override
    public Header getAuthHeader() {
        return authHeader;
    }

    private SSLContext generateSSLContext(String protocol, Logger log) {
        SSLContext sslContext = null;
        try {
            sslContext = SSLContextBuilder.create().setProtocol(protocol).build();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            log.warn("Failed to build SSL context error was: " + e.getMessage());
        }
        return sslContext;
    }

    private StringEntity generateEntity() throws CxRestLoginClientException, IOException {
        final String clientId = "cxsast_client";
        final String redirectUri = "%2Fcxwebclient%2FauthCallback.html%3F";
        final String responseType = "id_token%20token";
        final String nonce = "9313f0902ba64e50bc564f5137f35a52";
        final String isPrompt = "true";
        final String scopes = "sast_api openid sast-permissions access-control-permissions access_control_api management_and_orchestration_api".replace(" ", "%20");
        final String providerId = getProviderId("Windows");

        String redirectUrl = MessageFormat.format("/CxRestAPI/auth/identity/connect/authorize/callback" +
                        "?client_id={0}" +
                        "&redirect_uri={1}" + redirectUri +
                        "&response_type={2}" +
                        "&scope={3}" +
                        "&nonce={4}" +
                        "&prompt={5}"
                , clientId, hostName, responseType, scopes, nonce, isPrompt);

        try {
            List<NameValuePair> urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("redirectUrl", redirectUrl));
            urlParameters.add(new BasicNameValuePair("providerid", providerId));
            return new UrlEncodedFormEntity(urlParameters, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new CxRestLoginClientException(e.getMessage());
        }
    }

    private String getProviderId(String providerName) throws IOException, CxRestLoginClientException {
        final HttpUriRequest request = RequestBuilder.get(hostName + AUTH_API_URL + "AuthenticationProviders")
                .build();
        final HttpResponse response = client.execute(request);

        String entity = EntityUtils.toString(response.getEntity());
        final Provider[] providers = new Gson().fromJson(entity, Provider[].class);
        final Provider provider = Arrays.stream(providers)
                .filter(p -> p.getName().equalsIgnoreCase(providerName))
                .findFirst()
                .orElseThrow(() -> new CxRestLoginClientException(String.format("Provider [%s] was not found", providerName)));

        return String.valueOf(provider.getId());
    }
}