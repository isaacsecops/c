package com.checkmarx.cxconsole.commands;

import com.checkmarx.cxconsole.commands.constants.Commands;
import com.checkmarx.cxconsole.commands.exceptions.CLICommandException;
import com.checkmarx.cxconsole.commands.exceptions.CLICommandParameterValidatorException;
import com.checkmarx.cxconsole.commands.job.CLIOSAScanJob;
import com.checkmarx.cxconsole.commands.job.CLIScanJob;
import com.checkmarx.cxconsole.commands.utils.CommandParametersValidator;
import com.checkmarx.parameters.CLIScanParameters;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Created by nirli on 31/10/2017.
 */
class OSAScanCommandNew extends CLICommand {

    OSAScanCommandNew(CLIScanParameters params, boolean isAsyncScan) {
        super(params);
        this.isAsyncScan = isAsyncScan;
        if (isAsyncScan) {
            commandName = Commands.ASYNC_OSA_SCAN.value();
        } else {
            commandName = Commands.OSA_SCAN.value();
        }
    }

    @Override
    protected int executeCommand() throws CLICommandException {
        CLIScanJob job = null;
        if (!isAsyncScan) {
            job = new CLIOSAScanJob(params, false);
        } else {
            job = new CLIOSAScanJob(params, true);
        }

        Future<Integer> future = executor.submit(job);
        try {
            if (timeoutInSeconds != null) {
                exitCode = future.get(timeoutInSeconds, TimeUnit.SECONDS);
            } else {
                exitCode = future.get();
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Error executing OSA scan command: " + e.getMessage());
            throw new CLICommandException("Error executing OSA scan command: " + e.getMessage());
        }
        return exitCode;
    }


    @Override
    public void checkParameters() throws CLICommandParameterValidatorException {
        CommandParametersValidator.validateScanMandatoryParams(params);
        CommandParametersValidator.validateOSALocationType(params);
        CommandParametersValidator.validateOSAExcludedFilesFolder(params);
        CommandParametersValidator.validateServiceProviderFolder(params);
        if (isAsyncScan) {
            CommandParametersValidator.validateOSAAsyncScanParams(params);
        }
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public String getMandatoryParams() {
        return params.getCliOsaParameters().getMandatoryParams();
    }

    @Override
    public String getKeyDescriptions() {
        return params.getCliMandatoryParameters().getKeyDescriptions();
    }

    @Override
    public String getUsageExamples() {
        return "\n\nrunCxConsole.cmd OsaScan -v -Projectname SP\\Cx\\Engine\\AST -CxServer http://localhost -cxuser admin -cxpassword admin -osaLocationPath C:\\cx  -OsaFilesExclude *.class OsaPathExclude src,temp  \n"
                + "runCxConsole.cmd  OsaScan -v -projectname SP\\Cx\\Engine\\AST -cxserver http://localhost -cxuser admin -cxpassword admin -locationtype folder -locationurl http://vsts2003:8080 -locationuser dm\\matys -locationpassword XYZ  -OsaReportPDF -\n"
                + "runCxConsole.cmd  OsaScan -v -projectname SP\\Cx\\Engine\\AST -cxserver http://localhost -cxuser admin -cxpassword admin -locationtype shared -locationpath '\\storage\\path1;\\storage\\path2' -locationuser dm\\matys -locationpassword XYZ  -OsaReportPDF -OsaReportHTML -log a.log\n \n"
                + "runCxConsole.cmd  OsaScan -v -Projectname CxServer\\SP\\Company\\my project -CxServer http://localhost -cxuser admin -cxpassword admin -locationtype folder -locationpath C:\\Users\\some_project -OsaFilesExclude *.bat -OsaReportPDF";
    }

    @Override
    public void printHelp() {
        String header = "\nThe \"OsaScan\" command allows to scan existing projects for OSA. It accepts all project settings as an arguments, similar to the Web interface.";
        String footer = "\nUsage example: " + getUsageExamples() + "\n\n(c) 2017 CheckMarx.com LTD, All Rights Reserved\n";
        helpFormatter.printHelp(120, getCommandName(), header, params.getAllCLIOptions(), footer, true);
    }

    @Override
    public String getOptionalKeyDescriptions() {
        return null;
    }

    @Override
    public String getOptionalParams() {
        return null;
    }
}