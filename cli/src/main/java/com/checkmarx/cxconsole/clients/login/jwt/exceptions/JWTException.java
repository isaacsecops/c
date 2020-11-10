package com.checkmarx.cxconsole.clients.login.jwt.exceptions;

/**
 * Created by nirli on 17/10/2017.
 */
public class JWTException extends Exception {
    public JWTException() {
    }

    public JWTException(String message) {
        super(message);
    }

    public JWTException(String message, Throwable cause) {
        super(message, cause);
    }

    public JWTException(Throwable cause) {
        super(cause);
    }

    public JWTException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
