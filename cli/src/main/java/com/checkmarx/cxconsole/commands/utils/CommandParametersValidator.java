package com.checkmarx.cxconsole.commands.utils;

import com.checkmarx.cxconsole.commands.constants.LocationType;
import com.checkmarx.cxconsole.commands.exceptions.CLICommandParameterValidatorException;
import com.checkmarx.cxconsole.parameters.CLIScanParametersSingleton;
import com.google.common.base.Strings;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;

import java.io.*;


/**
 * Created by nirli on 31/10/2017.
 */
public class CommandParametersValidator {

    private CommandParametersValidator() {
        throw new IllegalStateException("Utility class");
    }

    private static Logger log = Logger.getLogger(CommandParametersValidator.class);

    private static final String MSG_ERR_SSO_WINDOWS_SUPPORT = "SSO login method is available only on Windows";
    private static final String MSG_ERR_MISSING_AUTHENTICATION_PARAMETERS = "Missing authentication parameters, please provide user name and password, token or use SSO login";
    private static final String MSG_ERR_2_AUTHENTICATION_METHODS = "Please provide only one authentication type: user name and password or token";
    private static final String MSG_ERR_MISSING_LOCATION_TYPE = "Missing locationType parameter";

    private static final String MSG_ERR_FOLDER_NOT_EXIST = "Specified source folder does not exist.";

    private static final String MSG_ERR_EXCLUDED_DIR = "Excluded folders list is invalid.";
    private static final String MSG_ERR_EXCLUDED_FILES = "Excluded files list is invalid.";
    private static final String MSG_ERR_INCLUDED_FILES = "Included files list is invalid.";
    private static final String MSG_ERR_EXTRACTABLE_FILES = "Extractable files list is invalid.";

    public static void validateGenerateTokenParams(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().isSsoLoginUsed() && !isWindows()) {
            throw new CLICommandParameterValidatorException(MSG_ERR_SSO_WINDOWS_SUPPORT);
        }

        if ((parameters.getCliMandatoryParameters().getOriginalHost() == null) ||
                (parameters.getCliMandatoryParameters().getUsername() == null) ||
                (parameters.getCliMandatoryParameters().getPassword() == null)) {
            throw new CLICommandParameterValidatorException("For token generation please provide: server, username and password");
        }
    }

    public static void validateRevokeTokenParams(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().isSsoLoginUsed() && !isWindows()) {
            throw new CLICommandParameterValidatorException(MSG_ERR_SSO_WINDOWS_SUPPORT);
        }

        if ((parameters.getCliMandatoryParameters().getOriginalHost() == null) || (parameters.getCliMandatoryParameters().getToken() == null)) {
            throw new CLICommandParameterValidatorException("For token revocation please provide: server and token");
        }
    }

    public static void validateScanMandatoryParams(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().isSsoLoginUsed() && !isWindows()) {
            throw new CLICommandParameterValidatorException(MSG_ERR_SSO_WINDOWS_SUPPORT);
        } else if ((!parameters.getCliMandatoryParameters().isHasUserParam() || !parameters.getCliMandatoryParameters().isHasPasswordParam()) && !parameters.getCliMandatoryParameters().isHasTokenParam() && !parameters.getCliSharedParameters().isSsoLoginUsed()) {
            throw new CLICommandParameterValidatorException(MSG_ERR_MISSING_AUTHENTICATION_PARAMETERS);
        } else if ((parameters.getCliMandatoryParameters().isHasUserParam() || parameters.getCliMandatoryParameters().isHasPasswordParam()) && parameters.getCliMandatoryParameters().isHasTokenParam()) {
            throw new CLICommandParameterValidatorException(MSG_ERR_2_AUTHENTICATION_METHODS);
        }

        if (parameters.getCliMandatoryParameters().getOriginalHost() == null || parameters.getCliMandatoryParameters().getHost() == null) {
            throw new CLICommandParameterValidatorException("Please provide server");
        }
        if (parameters.getCliMandatoryParameters().getProject() == null || parameters.getCliMandatoryParameters().getProject().getName() == null) {
            throw new CLICommandParameterValidatorException("Please provide project name");
        }
    }

    public static void validateSASTExcludedFilesFolder(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().isHasExcludedFoldersParam()) {
            String[] excludedFolders = parameters.getCliSastParameters().getExcludedFolders();
            if (excludedFolders == null || excludedFolders.length == 0) {
                throw new CLICommandParameterValidatorException(MSG_ERR_EXCLUDED_DIR);
            }
        }

        if (parameters.getCliSastParameters().isHasExcludedFilesParam()) {
            String[] excludedFiles = parameters.getCliSastParameters().getExcludedFiles();
            if (excludedFiles == null || excludedFiles.length == 0) {
                throw new CLICommandParameterValidatorException(MSG_ERR_EXCLUDED_FILES);
            }
        }
    }

    public static void validateOSAExcludedFilesFolder(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliOsaParameters().isHasOsaExcludedFoldersParam()) {
            String[] osaExcludedFolders = parameters.getCliOsaParameters().getOsaExcludedFolders();
            if (osaExcludedFolders == null || osaExcludedFolders.length == 0) {
                throw new CLICommandParameterValidatorException(MSG_ERR_EXCLUDED_DIR);
            }
        }

        if (parameters.getCliOsaParameters().isHasOsaExcludedFilesParam()) {
            String[] osaExcludedFiles = parameters.getCliOsaParameters().getOsaExcludedFiles();
            if (osaExcludedFiles == null || osaExcludedFiles.length == 0) {
                throw new CLICommandParameterValidatorException(MSG_ERR_EXCLUDED_FILES);
            }
        }
    }

    public static void validateOSAIncludedFiles(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliOsaParameters().isHasOsaIncludedFilesParam()) {
            String[] osaIncludedFiles = parameters.getCliOsaParameters().getOsaIncludedFiles();
            if (osaIncludedFiles == null || osaIncludedFiles.length == 0) {
                throw new CLICommandParameterValidatorException(MSG_ERR_INCLUDED_FILES);
            }
        }
    }

    public static void validateOSAExtractableFiles(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliOsaParameters().isHasOsaExtractableIncludeFilesParam()) {
            String[] osaExtractableFiles = parameters.getCliOsaParameters().getOsaExtractableIncludeFiles();
            if (osaExtractableFiles == null || osaExtractableFiles.length == 0) {
                throw new CLICommandParameterValidatorException(MSG_ERR_EXTRACTABLE_FILES);
            }
        }
    }

    public static void validatePrivateKeyLocationGITSVN(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().getLocationPrivateKeyFilePath() != null
                && parameters.getCliSharedParameters().getLocationType() != null
                && (parameters.getCliSharedParameters().getLocationType() == LocationType.GIT || parameters.getCliSharedParameters().getLocationType() == LocationType.SVN)) {
            File keyFile = new File(parameters.getCliSastParameters().getLocationPrivateKeyFilePath().trim());
            if (!keyFile.exists()) {
                throw new CLICommandParameterValidatorException("Private key file is not found in: " +
                        parameters.getCliSastParameters().getLocationPrivateKeyFilePath());
            }
            if (keyFile.isDirectory()) {
                throw new CLICommandParameterValidatorException("Private key file is a folder: " +
                        parameters.getCliSastParameters().getLocationPrivateKeyFilePath());
            }
        }
    }

    public static void validateOSALocationType(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliOsaParameters().getOsaLocationPath() == null &&
                (parameters.getCliSharedParameters().getLocationType() != LocationType.FOLDER && parameters.getCliSharedParameters().getLocationType() != LocationType.SHARED)) {
//            if (Strings.isNullOrEmpty(parameters.getCliOsaParameters().getOsaDockerImageName()) && Strings.isNullOrEmpty(parameters.getCliOsaParameters().getExcludeDockerPattern())) {
//                throw new CLICommandParameterValidatorException("For OSA Scan (OsaScan), provide  OsaLocationPath  or locationType (values: folder/shared)");
//            }
            throw new CLICommandParameterValidatorException("For OSA Scan (OsaScan), provide  OsaLocationPath  or locationType (values: folder/shared)");
        }
    }

    public static void validateSASTLocationType(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().getLocationType() == null) {
            throw new CLICommandParameterValidatorException(MSG_ERR_MISSING_LOCATION_TYPE);
        }

        switch (parameters.getCliSharedParameters().getLocationType().toString().toLowerCase()) {
            case ("folder"):
                validateFolder(parameters);
                validateWorkspaceParameterOnlyInPerforce(parameters);
                break;
            case ("shared"):
                validateShared(parameters);
                validateWorkspaceParameterOnlyInPerforce(parameters);
                break;
            case ("tfs"):
                validateTFS(parameters);
                validateWorkspaceParameterOnlyInPerforce(parameters);
                validateLocationPort(parameters);
                break;
            case ("svn"):
                validateSVN(parameters);
                validateWorkspaceParameterOnlyInPerforce(parameters);
                validateLocationPort(parameters);
                break;
            case ("perforce"):
                validatePerforce(parameters);
                validateWorkspaceParameterOnlyInPerforce(parameters);
                break;
            case ("git"):
                validateGIT(parameters);
                validateWorkspaceParameterOnlyInPerforce(parameters);
                break;
            default:
                throw new CLICommandParameterValidatorException("Error validate SAST location type");
        }
    }

    public static void validateServiceProviderFolder(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().getSpFolderName() != null) {
            File projectDir = new File(parameters.getCliSharedParameters().getSpFolderName().trim());
            if (!projectDir.exists()) {
                throw new CLICommandParameterValidatorException(MSG_ERR_FOLDER_NOT_EXIST + "["
                        + parameters.getCliSharedParameters().getSpFolderName() + "]");
            }

            if (!projectDir.isDirectory()) {
                throw new CLICommandParameterValidatorException(MSG_ERR_FOLDER_NOT_EXIST + "["
                        + parameters.getCliSharedParameters().getSpFolderName() + "]");
            }
        }
    }

    public static void validateEnableOSA(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().isOsaEnabled() &&
                (parameters.getCliSharedParameters().getLocationPath() == null ||
                        (parameters.getCliSharedParameters().getLocationType() != LocationType.FOLDER && parameters.getCliSharedParameters().getLocationType() != LocationType.SHARED))) {
            throw new CLICommandParameterValidatorException("For OSA Scan with EnableOsa parameter, provide  locationPath  or locationType ( values: folder/shared)");
        }

        validateScanDepthIsNumber(parameters);
        validateOsaDisabledReportsParams(parameters);
    }

    public static void validateSASTAsyncScanParams(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (!parameters.getCliSastParameters().getReportsPath().isEmpty()) {
            throw new CLICommandParameterValidatorException("Asynchronous run does not allow report creation. Please remove the report parameters and run again");
        }
        if (parameters.getCliSastParameters().getSastHighThresholdValue() != Integer.MAX_VALUE ||
                parameters.getCliSastParameters().getSastMediumThresholdValue() != Integer.MAX_VALUE ||
                parameters.getCliSastParameters().getSastLowThresholdValue() != Integer.MAX_VALUE) {
            throw new CLICommandParameterValidatorException("Asynchronous run does not support threshold. Please remove the threshold parameters and run again");
        }
    }

    public static void validateOSAAsyncScanParams(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliOsaParameters().getOsaJson() != null
                || parameters.getCliOsaParameters().getOsaReportPDF() != null
                || parameters.getCliOsaParameters().getOsaReportHTML() != null) {
            throw new CLICommandParameterValidatorException("Asynchronous run does not allow report creation. Please remove the report parameters and run again");
        }

        if (parameters.getCliOsaParameters().getOsaHighThresholdValue() != Integer.MAX_VALUE ||
                parameters.getCliOsaParameters().getOsaMediumThresholdValue() != Integer.MAX_VALUE ||
                parameters.getCliOsaParameters().getOsaLowThresholdValue() != Integer.MAX_VALUE) {
            throw new CLICommandParameterValidatorException("Asynchronous run does not support threshold. Please remove the threshold parameters and run again");
        }
    }

    private static boolean isWindows() {
        return (System.getProperty("os.name").contains("Windows"));
    }

    private static void validateFolder(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().getLocationPath() == null) {
            throw new CLICommandParameterValidatorException("locationPath parameter is not specified. Required when locationType parameter is folder");
        }
    }

    private static void validateShared(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().getLocationPath() == null) {
            throw new CLICommandParameterValidatorException("locationPath is not specified. Required when locationType is shared");
        }

        if (parameters.getCliSastParameters().getLocationUser() == null) {
            throw new CLICommandParameterValidatorException("locationUser is not specified. Required when locationType is shared");
        }

        if (parameters.getCliSastParameters().getLocationPass() == null) {
            throw new CLICommandParameterValidatorException("locationPassword is not specified. Required when locationType is shared");
        }
    }

    private static void validateTFS(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().getLocationPass() == null) {
            throw new CLICommandParameterValidatorException("locationPassword is not specified. Required when locationType is TFS");
        }

        if (parameters.getCliSastParameters().getLocationURL() == null) {
            throw new CLICommandParameterValidatorException("locationURL is not specified. Required when locationType is TFS");
        }

        if (parameters.getCliSastParameters().getLocationUser() == null) {
            throw new CLICommandParameterValidatorException("locationUser is not specified. Required when locationType is TFS");
        }

        if (parameters.getCliSharedParameters().getLocationPath() == null) {
            throw new CLICommandParameterValidatorException("locationPath is not specified. Required when locationType is TFS");
        }
    }

    private static void validateSVN(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().getLocationURL() == null) {
            throw new CLICommandParameterValidatorException("locationURL is not specified. Required when locationType is SVN");
        }

        if (parameters.getCliSharedParameters().getLocationPath() == null) {
            throw new CLICommandParameterValidatorException("locationPath is not specified. Required when locationType is SVN");
        }
    }

    private static void validateGIT(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().getLocationURL() == null) {
            throw new CLICommandParameterValidatorException("locationURL is not specified. Required when locationType is GIT");
        }

        if (parameters.getCliSastParameters().getLocationBranch() == null) {
            throw new CLICommandParameterValidatorException("locationBranch is not specified. Required when locationType is GIT");
        }
    }

    private static void validatePerforce(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().getLocationURL() == null) {
            throw new CLICommandParameterValidatorException("locationURL is not specified. Required when locationType is Perforce");
        }

        if (parameters.getCliSastParameters().getLocationUser() == null) {
            throw new CLICommandParameterValidatorException("locationUser is not specified. Required when locationType is Perforce");
        }

        if (parameters.getCliSharedParameters().getLocationPath() == null) {
            throw new CLICommandParameterValidatorException("locationPath is not specified. Required when locationType is Perforce");
        }
    }

    private static void validateWorkspaceParameterOnlyInPerforce(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSharedParameters().getLocationType() != null &&
                parameters.getCliSharedParameters().getLocationType() != LocationType.PERFORCE && parameters.getCliSastParameters().getPerforceWorkspaceMode() != null) {
            throw new CLICommandParameterValidatorException("WorkspaceMode parameter should be specified only when locationType is Perforce");
        }
    }

    private static void validateLocationPort(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (parameters.getCliSastParameters().getLocationPort() == null) {
            throw new CLICommandParameterValidatorException("Invalid location port");
        }
    }

    public static void validateOsaDisabledReportsParams(CLIScanParametersSingleton parameters) {
        if (parameters.getCliOsaParameters().getOsaReportPDF() != null) {
            log.info("OsaReportPDF parameter is not supported in this CLI version");
        }

        if (parameters.getCliOsaParameters().getOsaReportHTML() != null) {
            log.info("OsaReportHTML parameter is not supported in this CLI version");
        }
    }

    public static void validateScanDepthIsNumber(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (!NumberUtils.isNumber(parameters.getCliOsaParameters().getOsaScanDepth())) {
            throw new CLICommandParameterValidatorException("OSA scan depth value is not a number");
        }

    }

    public static void validateDockerInstall(CLIScanParametersSingleton parameters) throws CLICommandParameterValidatorException {
        if (!Strings.isNullOrEmpty(parameters.getCliOsaParameters().getOsaDockerImageName())) {
            try {
                Runtime.getRuntime().exec("docker images");
            } catch (IOException e) {
                throw new CLICommandParameterValidatorException("Docker image OSA scanning cannot be executed, Docker is not detected on the machine", e);
            }
        }
    }
}