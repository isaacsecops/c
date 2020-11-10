package com.checkmarx.cxconsole.utils;

import com.checkmarx.cxconsole.clients.login.CxRestLoginClient;
import com.checkmarx.cxconsole.clients.login.CxRestLoginClientImpl;
import com.checkmarx.cxconsole.parameters.CLIScanParametersSingleton;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Class responsible for loading CxConsole properties from corresponding
 * config folder
 */
public class ConfigMgr {

    private static Logger log = Logger.getLogger(ConfigMgr.class);

    /*
     * Property keys
     */
    public static final String KEY_PROGRESS_INTERVAL = "scan.job.progress.interval";
    public static final String KEY_OSA_PROGRESS_INTERVAL = "scan.osa.job.progress.interval";
    public static final String KEY_RETIRES = "scan.job.connection.retries";
    public static final String REPORT_TIMEOUT = "scan.job.report.timeout";
    public static final String EXCLUDED_FOLDERS_TO_PACK = "scan.zip.ignored.folders";
    public static final String EXCLUDED_FILES_TO_PACK = "scan.zip.ignored.files";
    public static final String KEY_OSA_INCLUDED_FILES = "scan.osa.include.files";
    public static final String KEY_OSA_EXCLUDED_FILES = "scan.osa.exclude.files";
    public static final String KEY_OSA_EXTRACTABLE_INCLUDE_FILES = "scan.osa.extractable.include.files";
    public static final String KEY_OSA_SCAN_DEPTH = "scan.osa.extractable.depth";
    public static final String KEY_MAX_ZIP_SIZE = "scan.zip.max_size";
    public static final String KEY_DEF_PROJECT_NAME = "scan.default.projectname";
    public static final String KEY_VERSION = "cxconsole.version";
    public static final String KEY_USE_KERBEROS_AUTH = "use_kerberos_authentication";
    public static final String KEY_KERBEROS_USERNAME = "kerberos.username";

    private String separator = FileSystems.getDefault().getSeparator();
    private String userDir = System.getProperty("user.dir");

    private String configDirRelativePath = "config";
    private String configFile = "cx_console.properties";

    private String defaultPath = userDir + separator + configDirRelativePath + separator + configFile;
    private Properties applicationProperties;
    private static CxRestLoginClient cxRestLoginClient;

    private static ConfigMgr mgr;

    private ConfigMgr(String defConfig) {
        applicationProperties = new Properties();
        loadProperties(defConfig);
    }

    protected void loadProperties(String confPath) {
        try {
            if (confPath != null && loadFromConfigParam(confPath)) {
                log.info("Config file location: " + confPath);
                return;
            }

            if (!loadConfigFromFile(defaultPath) || applicationProperties.isEmpty()) {
                log.warn("Error occurred during loading configuration file. Default configuration values will be loaded.");
                loadDefaults();
            }

            log.info("Default configuration file location: " + defaultPath);
        } catch (Exception ex) {
            log.warn("Error occurred during loading configuration file.");
        }
    }

    private boolean loadFromConfigParam(String confPath) {
        try {
            confPath = Paths.get(confPath).toFile().getCanonicalPath();
        } catch (Exception ex) {
            log.warn("Error occurred during loading configuration file. The Config path is invalid.");
            return false;
        }
        return loadConfigFromFile(confPath);
    }

    private boolean loadConfigFromFile(String path) {
        boolean ret = false;
        if (new File(path).exists()) {
            try (FileInputStream in = new FileInputStream(path)) {
                applicationProperties.load(in);

                ret = true;
            } catch (Exception e) {
                log.error("Error occurred during loading CxConsole properties.");
            }
        } else {
            log.error("The specified configuration path: [" + path + "] does not exist.");
        }
        return ret;
    }

    protected void loadDefaults() {
        applicationProperties.put(REPORT_TIMEOUT, "30");
        applicationProperties.put(KEY_PROGRESS_INTERVAL, "15");
        applicationProperties.put(KEY_OSA_PROGRESS_INTERVAL, "5");
        applicationProperties.put(KEY_RETIRES, "3");
        applicationProperties.put(EXCLUDED_FOLDERS_TO_PACK, "_cvs, .svn, .hg, .git, .bzr, bin, obj, backup");
        applicationProperties.put(EXCLUDED_FILES_TO_PACK, "*.DS_Store, *.ipr, *.iws, *.bak, *.tmp, *.aac, *.aif, *.iff, *.m3u, *.mid, *.mp3, *.mpa, *.ra, *.wav, *.wma, *.3g2, *.3gp, *.asf, *.asx, *.avi, *.flv, *.mov, *.mp4, *.mpg, *.rm, *.swf, *.vob, *.wmv, *.bmp, *.gif, *.jpg, *.png, *.psd, *.tif, *.jar, *.zip, *.rar, *.exe, *.dll, *.pdb, *.7z, *.gz, *.tar.gz, *.tar, *.ahtm, *.ahtml, *.fhtml, *.hdm, *.hdml, *.hsql, *.ht, *.hta, *.htc, *.htd, *.htmls, *.ihtml, *.mht, *.mhtm, *.mhtml, *.ssi, *.stm, *.stml, *.ttml, *.txn, *.xhtm, *.xhtml, *.class, *.iml");
        applicationProperties.put(KEY_MAX_ZIP_SIZE, "200");
        applicationProperties.put(KEY_DEF_PROJECT_NAME, "console.project");
        applicationProperties.put(KEY_VERSION, ConsoleUtils.getBuildVersion());
        applicationProperties.put(KEY_USE_KERBEROS_AUTH, "false");
        applicationProperties.put(KEY_KERBEROS_USERNAME, "");
        applicationProperties.put("kerberos.password", "");

        File propsFile = new File(defaultPath);
        if (!propsFile.exists()) {
            File configDir = new File(userDir + separator + configDirRelativePath);
            if (!configDir.exists()) {
                configDir.mkdir();
            }
            try (FileOutputStream fOut = new FileOutputStream(propsFile)) {
                applicationProperties.store(fOut, "");
            } catch (IOException e) {
                log.warn("Cannot create configuration file");
            }
        }
    }

    public String getProperty(String key) {
        Object value = applicationProperties.get(key);
        return value == null ? null : value.toString();
    }

    public Integer getIntProperty(String key) {
        Object value = applicationProperties.get(key);
        Integer intValue = null;
        if (value != null) {
            try {
                intValue = Integer.parseInt(value.toString());
            } catch (NumberFormatException e) {
                log.warn("Can't parse string to int value: " + e.getMessage());
            }
        }
        return intValue;
    }

    public Long getLongProperty(String key) {
        Object value = applicationProperties.get(key);
        Long longValue = null;
        if (value != null) {
            try {
                longValue = Long.parseLong(value.toString());
            } catch (NumberFormatException e) {
                log.warn("Can't parse string to long value: " + e.getMessage());
            }
        }
        return longValue;
    }

    public static ConfigMgr getCfgMgr() {
        return mgr;
    }

    public static void initCfgMgr(String defConfig) {
        mgr = new ConfigMgr(defConfig);
    }

    public static CxRestLoginClient getRestWSMgr(CLIScanParametersSingleton parameters) {
        if (cxRestLoginClient == null) {
            if (parameters.getCliMandatoryParameters().isHasUserParam() && parameters.getCliMandatoryParameters().isHasPasswordParam()) {
                cxRestLoginClient = new CxRestLoginClientImpl(parameters.getCliMandatoryParameters().getOriginalHost(), parameters.getCliMandatoryParameters().getUsername(), parameters.getCliMandatoryParameters().getPassword());
            } else if (parameters.getCliMandatoryParameters().isHasTokenParam()) {
                cxRestLoginClient = new CxRestLoginClientImpl(parameters.getCliMandatoryParameters().getOriginalHost(), parameters.getCliMandatoryParameters().getToken());
            } else if (parameters.getCliSharedParameters().isSsoLoginUsed()) {
                cxRestLoginClient = new CxRestLoginClientImpl(parameters.getCliMandatoryParameters().getHost());
            }
        }

        return cxRestLoginClient;
    }
}
