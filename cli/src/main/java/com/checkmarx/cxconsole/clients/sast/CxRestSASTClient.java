package com.checkmarx.cxconsole.clients.sast;

import com.checkmarx.cxconsole.clients.arm.dto.CxArmConfig;
import com.checkmarx.cxconsole.clients.exception.CxRestClientException;
import com.checkmarx.cxconsole.clients.general.CxRestClient;
import com.checkmarx.cxconsole.clients.osa.exceptions.CxRestOSAClientException;
import com.checkmarx.cxconsole.clients.sast.constants.RemoteSourceType;
import com.checkmarx.cxconsole.clients.sast.constants.ReportStatusValue;
import com.checkmarx.cxconsole.clients.sast.constants.ReportType;
import com.checkmarx.cxconsole.clients.sast.dto.*;
import com.checkmarx.cxconsole.clients.sast.exceptions.CxRestSASTClientException;

import java.io.File;
import java.net.URL;
import java.util.List;

/**
 * Created by nirli on 01/03/2018.
 */
public interface CxRestSASTClient<T extends RemoteSourceScanSettingDTO> extends CxRestClient {

    List<PresetDTO> getSastPresets() throws CxRestSASTClientException;

    List<EngineConfigurationDTO> getEngineConfiguration() throws CxRestSASTClientException;

    ScanSettingDTO getProjectScanSetting(int id) throws CxRestSASTClientException;

    void createProjectScanSetting(ScanSettingDTO scanSetting) throws CxRestSASTClientException;

    void updateProjectScanSetting(ScanSettingDTO scanSetting) throws CxRestSASTClientException;

    int createNewSastScan(int projectId, boolean forceScan, boolean incrementalScan, boolean visibleOthers) throws CxRestSASTClientException;

    void updateScanExclusions(int projectId, String[] excludeFoldersPattern, String[] excludeFilesPattern) throws CxRestSASTClientException;

    void updateScanComment(long scanId, String comment) throws CxRestSASTClientException;

    void uploadZipFileForSASTScan(int projectId, byte[] zipFile) throws CxRestSASTClientException;

    ScanQueueDTO getScanQueueResponse(long scanId) throws CxRestSASTClientException;

    void createRemoteSourceScan(int projectId, T remoteSourceScanSettingDTO, RemoteSourceType remoteSourceType) throws CxRestSASTClientException;

    void createGITScan(int projectId, String locationURL, String locationBranch, byte[] privateKey) throws CxRestSASTClientException;

    int createReport(long scanId, ReportType reportType) throws CxRestSASTClientException;

    ReportStatusValue getReportStatus(int reportId) throws CxRestSASTClientException;

    void createReportFile(int reportId, File reportFile) throws CxRestSASTClientException;

    ResultsStatisticsDTO getScanResults(long scanId) throws CxRestSASTClientException;

    CxArmConfig getCxArmConfiguration() throws CxRestOSAClientException;

    String getSastVersion() throws CxRestSASTClientException;

    /**
     * @deprecated This method will be removed starting from 9.30 as Access Control does not support access tokens
     */
    @Deprecated
    String generateToken(URL serverUrl, String userName, String password) throws CxRestClientException;

    /**
     * @deprecated This method will be removed starting from 9.30 as Access Control does not support access tokens
     */
    @Deprecated
    void revokeToken(URL serverUrl, String token) throws CxRestClientException;

}
