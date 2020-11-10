package com.checkmarx.cxconsole.commands.job.utils;

import com.checkmarx.cxconsole.clients.osa.dto.OSASummaryResults;
import com.checkmarx.cxconsole.clients.sast.dto.ResultsStatisticsDTO;
import org.apache.log4j.Logger;

/**
 * Created by nirli on 06/11/2017.
 */
public class PrintResultsUtils {

    private static final String LINE_SPACER = "------------------------";
    private static final String RESULT_FOOTER = "-----------------------------------------------------------------------------------------";

    private static Logger log = Logger.getLogger(PrintResultsUtils.class);

    private PrintResultsUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static void printOSAResultsToConsole(OSASummaryResults osaSummaryResults, String osaProjectSummaryLink) {
        log.info("----------------------------Checkmarx Scan Results(CxOSA):-------------------------------");
        log.info("");
        log.info(LINE_SPACER);
        log.info("OSA vulnerabilities Summary:");
        log.info(LINE_SPACER);
        log.info("OSA high severity results: " + osaSummaryResults.getTotalHighVulnerabilities());
        log.info("OSA medium severity results: " + osaSummaryResults.getTotalMediumVulnerabilities());
        log.info("OSA low severity results: " + osaSummaryResults.getTotalLowVulnerabilities());
        log.info("Vulnerability score: " + osaSummaryResults.getVulnerabilityScore());
        log.info("");
        log.info(LINE_SPACER);
        log.info("Libraries Scan Results:");
        log.info(LINE_SPACER);
        log.info("Open-source libraries: " + osaSummaryResults.getTotalLibraries());
        log.info("Vulnerable and outdated: " + osaSummaryResults.getVulnerableAndOutdated());
        log.info("Vulnerable and updated: " + osaSummaryResults.getVulnerableAndUpdated());
        log.info("Non-vulnerable libraries: " + osaSummaryResults.getNonVulnerableLibraries());
        log.info("");
        log.info("");
        log.info("OSA scan results location: " + osaProjectSummaryLink);
        log.info(RESULT_FOOTER);
    }

    public static void printSASTResultsToConsole(ResultsStatisticsDTO scanResults) {
        log.info("----------------------------Checkmarx Scan Results(CxSAST):-------------------------------");
        log.info("");
        log.info(LINE_SPACER);
        log.info("SAST vulnerabilities Summary:");
        log.info(LINE_SPACER);
        log.info("SAST high severity results: " + scanResults.getHighSeverity());
        log.info("SAST medium severity results: " + scanResults.getMediumSeverity());
        log.info("SAST low severity results: " + scanResults.getLowSeverity());
        log.info("");
        log.info(RESULT_FOOTER);
    }

}
