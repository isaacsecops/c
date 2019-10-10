package com.checkmarx.cxconsole.clients.login;

import com.checkmarx.cxconsole.clients.exception.CxRestClientException;
import com.checkmarx.cxconsole.clients.login.exceptions.CxRestLoginClientException;
import org.apache.http.client.HttpClient;

/**
 * Created by nirli on 14/03/2018.
 */
public interface CxRestLoginClient {

    void credentialsLogin() throws CxRestLoginClientException;

    void tokenLogin() throws CxRestClientException;

    void ssoLogin() throws CxRestClientException;

    HttpClient getClient();

    String getHostName();

    boolean isLoggedIn();

    boolean isCredentialsLogin();

    boolean isTokenLogin();
}
