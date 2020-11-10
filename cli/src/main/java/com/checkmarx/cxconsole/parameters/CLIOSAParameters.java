package com.checkmarx.cxconsole.parameters;

import com.checkmarx.cxconsole.parameters.exceptions.CLIParameterParsingException;
import com.checkmarx.cxconsole.parameters.utils.ParametersUtils;
import com.checkmarx.cxconsole.utils.ConfigMgr;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;

import java.io.File;

import static com.checkmarx.cxconsole.utils.ConfigMgr.*;

/**
 * Created by nirli on 29/10/2017.
 */
public class CLIOSAParameters extends AbstractCLIScanParameters {

    /**
     * Definition of command line parameters to be used by Apache CLI parser
     */
    private Options commandLineOptions;

    private static final int UNASSIGNED_VALUE = Integer.MAX_VALUE;

    private CLIMandatoryParameters cliMandatoryParameters;

    private boolean isOsaThresholdEnabled = false;
    private int osaLowThresholdValue = UNASSIGNED_VALUE;
    private int osaMediumThresholdValue = UNASSIGNED_VALUE;
    private int osaHighThresholdValue = UNASSIGNED_VALUE;
    private static final String SPLIT_REGEX = "\\s*,\\s*";

    private String[] osaLocationPath = new String[]{};
    private String[] osaExcludedFolders = new String[]{};
    private boolean hasOsaExcludedFoldersParam = false;
    private String[] osaExcludedFiles = new String[]{};
    private boolean hasOsaExcludedFilesParam = false;
    private String[] osaIncludedFiles = new String[]{};
    private boolean hasOsaIncludedFilesParam = false;
    private String[] osaExtractableIncludeFiles = new String[]{};
    private boolean hasOsaExtractableIncludeFilesParam = false;
    private String osaScanDepth;
    private String osaReportPDF;
    private String osaReportHTML;
    private String osaJson;
    private boolean executeNpmAndBower = false;
    private boolean executePackageDependency = false;
    private boolean checkPolicyViolations = false;
    private String osaDockerImageName;
    private String excludeDockerPattern;
    private String osaResultsLogPath;

    private static final Option PARAM_OSA_LOCATION_PATH = Option.builder("osalocationpath").hasArgs().argName("folders list").desc("Comma separated list of folder path patterns(Local or shared path ) to OSA sources.")
            .valueSeparator(',').build();

    private static final Option PARAM_OSA_PDF_FILE = Option.builder("osareportpdf").hasArg(true).optionalArg(true).argName("file").desc("Name or path to OSA PDF report . Optional.").build();
    private static final Option PARAM_OSA_HTML_FILE = Option.builder("osareporthtml").hasArg(true).optionalArg(true).argName("file").desc("Name or path to OSA HTML report. Optional.").build();
    private static final Option PARAM_OSA_JSON = Option.builder("osajson").hasArg(true).optionalArg(true).argName("file").desc("Name or path to OSA scan results (libraries and vulnerabilities) in Json format. Optional.").build();

    private static final Option PARAM_OSA_EXCLUDE_FILES = Option.builder("osafilesexclude").hasArg(true).hasArgs().argName("files list").desc("Comma separated list of file name patterns to exclude from OSA scan. Example: '-OsaFilesExclude *.class' excludes all files with '.class' extension. Optional.")
            .valueSeparator(',').build();
    private static final Option PARAM_OSA_INCLUDE_FILES = Option.builder("osafilesinclude").hasArg(true).hasArgs().argName("folders list").desc("Comma separated list of files extension to include in OSA scan. Example: '-OsaFilesInclude *.bin' include only files with .bin extension. Optional.")
            .valueSeparator(',').build();
    private static final Option PARAM_OSA_EXCLUDE_FOLDERS = Option.builder("osapathexclude").hasArg(true).hasArgs().argName("folders list").desc("Comma separated list of folder path patterns to exclude from OSA scan. Example: '-OsaPathExclude test' excludes all folders which start with 'test' prefix. Optional.")
            .valueSeparator(',').build();
    private static final Option PARAM_OSA_EXTRACTABLE_INCLUDE_FILES = Option.builder("osaarchivetoextract").hasArg(true).hasArgs().argName("folders list").desc("Comma separated list of files extension to be extracted for OSA scan. Example: '-OSAArchiveIncludes *.zip' extracts only files with .zip extension. Optional.")
            .valueSeparator(',').build();
    private static final Option PARAM_OSA_SCAN_DEPTH = Option.builder("osascandepth").hasArg(true).argName("OSA analysis unzip depth").desc("Extraction depth for files to send for OSA analysis. Optional.").build();

    private static final Option PARAM_OSA_LOW_THRESHOLD = Option.builder("osalow").hasArg(true).argName("number of low OSA vulnerabilities").desc("OSA low severity vulnerability threshold. If the number of low vulnerabilities exceeds the threshold, scan will end with an error. Optional.").build();
    private static final Option PARAM_OSA_MEDIUM_THRESHOLD = Option.builder("osamedium").hasArg(true).argName("number of medium OSA vulnerabilities").desc("OSA medium severity vulnerability threshold. If the number of medium vulnerabilities exceeds the threshold, scan will end with an error. Optional.").build();
    private static final Option PARAM_OSA_HIGH_THRESHOLD = Option.builder("osahigh").hasArg(true).argName("number of high OSA vulnerabilities").desc("OSA high severity vulnerability threshold. If the number of high vulnerabilities exceeds the threshold, scan will end with an error. Optional.").build();

    private static final Option PARAM_OSA_EXECUTE_NPM_AND_BOWER = Option.builder("executenpmandbower").hasArg(false).argName("Pre scan installation of package managers dependencies").desc("Triggered in order to perform install dependencies command for package managers before initiate OSA analysis. Optional.(Currently kept for backward compatibility and will be removed in the future. You should use packagedependencyinstall instead)").build();
    private static final Option PARAM_OSA_EXECUTE_PACKAGE_INSTALL = Option.builder("executepackagedependency").hasArg(false).argName("Pre scan installation of package managers dependencies").desc("Triggered in order to perform install dependencies command for package managers before initiate OSA analysis. Optional.").build();
    private static final Option PARAM_RUN_POLICY_VIOLATIONS = Option.builder("checkpolicy").hasArg(false).argName("Check Policy Violations").desc("Mark the build as failed or unstable if the project's policy is violated. Optional.").build();
//    private static final Option PARAM_OSA_SCAN_DOCKER = Option.builder("dockerscan").hasArg(true).argName("Docker image name").desc("Supports scanning of docker images as part of the OSA scan. Optional.").build();
//    private static final Option PARAM_DOCKER_EXCLUDE = Option.builder("dockerexcludescan").hasArg(true).argName("Docker exclude pattern").desc("Set the GLOB pattern property for excluding docker files to scan. Optional.").build();

    private static final Option PARAM_OAS_RESULTS_LOG = Option.builder("osaresultslog").hasArg(true).argName("Path to osa results log").desc("Set the path for osa results log. Optional.").build();

    CLIOSAParameters() throws CLIParameterParsingException {
        initCommandLineOptions();
    }

    void initOsaParams(CommandLine parsedCommandLineArguments) {
        osaLocationPath = parsedCommandLineArguments.getOptionValues(PARAM_OSA_LOCATION_PATH.getOpt());

        hasOsaExcludedFoldersParam = parsedCommandLineArguments.hasOption(PARAM_OSA_EXCLUDE_FOLDERS.getOpt());
        osaExcludedFolders = parsedCommandLineArguments.getOptionValues(PARAM_OSA_EXCLUDE_FOLDERS.getOpt());
        hasOsaExcludedFilesParam = parsedCommandLineArguments.hasOption(PARAM_OSA_EXCLUDE_FILES.getOpt());
        osaExcludedFiles = parsedCommandLineArguments.getOptionValues(PARAM_OSA_EXCLUDE_FILES.getOpt());
        hasOsaIncludedFilesParam = parsedCommandLineArguments.hasOption(PARAM_OSA_INCLUDE_FILES.getOpt());
        osaIncludedFiles = parsedCommandLineArguments.getOptionValues(PARAM_OSA_INCLUDE_FILES.getOpt());
        hasOsaExtractableIncludeFilesParam = parsedCommandLineArguments.hasOption(PARAM_OSA_EXTRACTABLE_INCLUDE_FILES.getOpt());
        osaExtractableIncludeFiles = parsedCommandLineArguments.getOptionValues(PARAM_OSA_EXTRACTABLE_INCLUDE_FILES.getOpt());
        osaReportHTML = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_OSA_HTML_FILE.getOpt());
        osaReportPDF = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_OSA_PDF_FILE.getOpt());
        osaJson = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_OSA_JSON.getOpt());
        osaScanDepth = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_OSA_SCAN_DEPTH.getOpt());
        String osaLowThresholdStr = parsedCommandLineArguments.getOptionValue(PARAM_OSA_LOW_THRESHOLD.getOpt());
        String osaMediumThresholdStr = parsedCommandLineArguments.getOptionValue(PARAM_OSA_MEDIUM_THRESHOLD.getOpt());
        String osaHighThresholdStr = parsedCommandLineArguments.getOptionValue(PARAM_OSA_HIGH_THRESHOLD.getOpt());
        executeNpmAndBower = parsedCommandLineArguments.hasOption(PARAM_OSA_EXECUTE_NPM_AND_BOWER.getOpt());
        executePackageDependency = parsedCommandLineArguments.hasOption(PARAM_OSA_EXECUTE_PACKAGE_INSTALL.getOpt());
        checkPolicyViolations = parsedCommandLineArguments.hasOption(PARAM_RUN_POLICY_VIOLATIONS.getOpt());
//        osaDockerImageName = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_OSA_SCAN_DOCKER.getOpt());
//        excludeDockerPattern = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_DOCKER_EXCLUDE.getOpt());
        osaResultsLogPath = ParametersUtils.getOptionalValue(parsedCommandLineArguments, PARAM_OAS_RESULTS_LOG.getOpt());

        if(osaResultsLogPath == null){
            String path = System.getProperty("user.dir");
            osaResultsLogPath = path + File.separator + "logs";
        }

        if (osaScanDepth == null) {
            osaScanDepth = ConfigMgr.getCfgMgr().getProperty(KEY_OSA_SCAN_DEPTH);
        }

        if (!hasOsaExcludedFilesParam) {
            osaExcludedFiles = (ConfigMgr.getCfgMgr().getProperty(KEY_OSA_EXCLUDED_FILES)).split(SPLIT_REGEX);
        }
        cleanExtensionList(osaExcludedFiles);

        if (!hasOsaIncludedFilesParam) {
            osaIncludedFiles = (ConfigMgr.getCfgMgr().getProperty(KEY_OSA_INCLUDED_FILES)).split(SPLIT_REGEX);
        }
        cleanExtensionList(osaIncludedFiles);

        if (!hasOsaExtractableIncludeFilesParam) {
            osaExtractableIncludeFiles = (ConfigMgr.getCfgMgr().getProperty(KEY_OSA_EXTRACTABLE_INCLUDE_FILES)).split(SPLIT_REGEX);
        }
        cleanExtensionList(osaExtractableIncludeFiles);

        if (!hasOsaExcludedFoldersParam) {
            osaExcludedFolders = parsedCommandLineArguments.getOptionValues(PARAM_OSA_EXCLUDE_FOLDERS.getOpt());
        }

        if (osaLowThresholdStr != null || osaMediumThresholdStr != null || osaHighThresholdStr != null) {
            isOsaThresholdEnabled = true;
            if (osaLowThresholdStr != null) {
                osaLowThresholdValue = Integer.parseInt(osaLowThresholdStr);
            }

            if (osaMediumThresholdStr != null) {
                osaMediumThresholdValue = Integer.parseInt(osaMediumThresholdStr);
            }

            if (osaHighThresholdStr != null) {
                osaHighThresholdValue = Integer.parseInt(osaHighThresholdStr);
            }
        }
    }

    private void cleanExtensionList(String[] osaScanDepth) {
        for (int i = 0; i < osaScanDepth.length; i++) {
            osaScanDepth[i] = osaScanDepth[i].replace("*.", "");
        }
    }

    public boolean isOsaThresholdEnabled() {
        return isOsaThresholdEnabled;
    }

    public int getOsaLowThresholdValue() {
        return osaLowThresholdValue;
    }

    public int getOsaMediumThresholdValue() {
        return osaMediumThresholdValue;
    }

    public int getOsaHighThresholdValue() {
        return osaHighThresholdValue;
    }

    public String[] getOsaLocationPath() {
        return osaLocationPath;
    }

    public String[] getOsaExcludedFolders() {
        return osaExcludedFolders;
    }

    public String[] getOsaExcludedFiles() {
        return osaExcludedFiles;
    }

    public String[] getOsaIncludedFiles() {
        return osaIncludedFiles;
    }

    public String getOsaReportPDF() {
        return osaReportPDF;
    }

    public String getOsaReportHTML() {
        return osaReportHTML;
    }

    public String getOsaJson() {
        return osaJson;
    }

    public Options getCommandLineOptions() {
        return commandLineOptions;
    }

    public boolean isHasOsaExcludedFoldersParam() {
        return hasOsaExcludedFoldersParam;
    }

    public boolean isHasOsaExcludedFilesParam() {
        return hasOsaExcludedFilesParam;
    }

    public boolean isHasOsaExtractableIncludeFilesParam() {
        return hasOsaExtractableIncludeFilesParam;
    }

    public String[] getOsaExtractableIncludeFiles() {
        return osaExtractableIncludeFiles;
    }

    public boolean isHasOsaIncludedFilesParam() {
        return hasOsaIncludedFilesParam;
    }

    public String getOsaScanDepth() {
        return osaScanDepth;
    }

    public boolean isExecuteNpmAndBower() {
        return executeNpmAndBower;
    }

    public boolean isExecutePackageDependency() {
        return executePackageDependency;
    }

    public boolean isCheckPolicyViolations() {
        return checkPolicyViolations;
    }

    public String getOsaDockerImageName() {
        return osaDockerImageName;
    }

    public String getExcludeDockerPattern() {
        return excludeDockerPattern == null ? "" : excludeDockerPattern;
    }

    @Override
    void initCommandLineOptions() {
        commandLineOptions = new Options();
        commandLineOptions.addOption(PARAM_OSA_PDF_FILE);
        commandLineOptions.addOption(PARAM_OSA_HTML_FILE);
        commandLineOptions.addOption(PARAM_OSA_JSON);
        commandLineOptions.addOption(PARAM_OSA_EXCLUDE_FOLDERS);
        commandLineOptions.addOption(PARAM_OSA_EXCLUDE_FILES);
        commandLineOptions.addOption(PARAM_OSA_INCLUDE_FILES);
        commandLineOptions.addOption(PARAM_OSA_LOCATION_PATH);
        commandLineOptions.addOption(PARAM_OSA_EXTRACTABLE_INCLUDE_FILES);

        commandLineOptions.addOption(PARAM_OSA_LOW_THRESHOLD);
        commandLineOptions.addOption(PARAM_OSA_MEDIUM_THRESHOLD);
        commandLineOptions.addOption(PARAM_OSA_HIGH_THRESHOLD);
        commandLineOptions.addOption(PARAM_OSA_SCAN_DEPTH);

        commandLineOptions.addOption(PARAM_OSA_EXECUTE_NPM_AND_BOWER);
        commandLineOptions.addOption(PARAM_OSA_EXECUTE_PACKAGE_INSTALL);
        commandLineOptions.addOption(PARAM_RUN_POLICY_VIOLATIONS);
//        commandLineOptions.addOption(PARAM_OSA_SCAN_DOCKER);
//        commandLineOptions.addOption(PARAM_DOCKER_EXCLUDE);

        commandLineOptions.addOption(PARAM_OAS_RESULTS_LOG);
    }

    @Override
    public String getMandatoryParams() {
        return cliMandatoryParameters.getMandatoryParams();
    }

    OptionGroup getOSAScanParamsOptionGroup() {
        OptionGroup osaParamsOptionGroup = new OptionGroup();
        for (Option opt : commandLineOptions.getOptions()) {
            osaParamsOptionGroup.addOption(opt);
        }

        return osaParamsOptionGroup;
    }

    public String getOsaResultsLogPath() {
        return osaResultsLogPath;
    }


}