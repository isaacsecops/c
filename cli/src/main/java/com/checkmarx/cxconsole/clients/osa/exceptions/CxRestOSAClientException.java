package com.checkmarx.cxconsole.clients.osa.exceptions;

import com.checkmarx.cxconsole.clients.exception.CxRestClientException;

/**
 * Created by nirli on 25/10/2017.
 */
public class CxRestOSAClientException extends CxRestClientException {
    public CxRestOSAClientException() {
    }

    public CxRestOSAClientException(String message) {
        super(message);
    }

    public CxRestOSAClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public CxRestOSAClientException(Throwable cause) {
        super(cause);
    }

    public CxRestOSAClientException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
