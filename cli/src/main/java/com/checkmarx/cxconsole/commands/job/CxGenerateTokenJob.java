package com.checkmarx.cxconsole.commands.job;

import com.checkmarx.cxconsole.clients.exception.CxRestClientException;
import com.checkmarx.cxconsole.commands.job.exceptions.CLITokenJobException;
import com.checkmarx.cxconsole.parameters.CLIMandatoryParameters;
import com.checkmarx.cxconsole.parameters.CLIScanParametersSingleton;

import java.net.MalformedURLException;
import java.net.URL;

import static com.checkmarx.cxconsole.exitcodes.Constants.ExitCodes.SCAN_SUCCEEDED_EXIT_CODE;

public class CxGenerateTokenJob extends CLITokenJob {

    private CLIMandatoryParameters mandatoryParamsContainer;

    public CxGenerateTokenJob(CLIScanParametersSingleton parameters) {
        super(parameters);
        mandatoryParamsContainer = params.getCliMandatoryParameters();
    }

    @Override
    public Integer call() throws CLITokenJobException {
        log.info("Trying to login to server: " + params.getCliMandatoryParameters().getOriginalHost());
        String token;
        try {
            token = cxRestTokenClient.generateToken(new URL(mandatoryParamsContainer.getOriginalHost()), mandatoryParamsContainer.getUsername(), mandatoryParamsContainer.getPassword());
        } catch (MalformedURLException | CxRestClientException e) {
            throw new CLITokenJobException("Fail to generate login token: " + e.getMessage());
        }
        log.info("The login token is: " + token);

        return SCAN_SUCCEEDED_EXIT_CODE;
    }

}