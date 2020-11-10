package com.checkmarx.cxconsole.commands.constants;

/**
 * Created by Galn on 06/04/2017.
 */
public enum Commands {
    SCAN("Scan"),
    ASYNC_SCAN("AsyncScan"),
    OSA_SCAN("OsaScan"),
    ASYNC_OSA_SCAN("AsyncOsaScan"),
    GENERATE_TOKEN("GenerateToken"),
    REVOKE_TOKEN("RevokeToken");

    private String value;

    public String value() {
        return value;
    }

    public String upperCaseValue() {
        return value.toUpperCase();
    }

    Commands(String value) {
        this.value = value;
    }
}