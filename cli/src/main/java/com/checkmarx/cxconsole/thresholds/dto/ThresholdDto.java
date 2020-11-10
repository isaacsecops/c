package com.checkmarx.cxconsole.thresholds.dto;

import com.checkmarx.cxconsole.clients.sast.dto.ResultsStatisticsDTO;
import com.checkmarx.cxconsole.constants.ScanType;

public class ThresholdDto {

    private ScanType scanType;

    private int highSeverityThreshold;
    private int mediumSeverityThreshold;
    private int lowSeverityThreshold;

    private int highSeverityScanResult;
    private int mediumSeverityScanResult;
    private int lowSeverityScanResult;

    public ThresholdDto(ScanType scanType, int highSeverityThreshold, int mediumSeverityThreshold, int lowSeverityThreshold, int highSeverityScanResult, int mediumSeverityScanResult, int lowSeverityScanResult) {
        this.scanType = scanType;
        this.highSeverityThreshold = highSeverityThreshold;
        this.mediumSeverityThreshold = mediumSeverityThreshold;
        this.lowSeverityThreshold = lowSeverityThreshold;
        this.highSeverityScanResult = highSeverityScanResult;
        this.mediumSeverityScanResult = mediumSeverityScanResult;
        this.lowSeverityScanResult = lowSeverityScanResult;
    }

    public ThresholdDto(int highSeverityThreshold, int mediumSeverityThreshold, int lowSeverityThreshold, ResultsStatisticsDTO sastResultsDTO) {
        this.scanType = ScanType.SAST_SCAN;
        this.highSeverityThreshold = highSeverityThreshold;
        this.mediumSeverityThreshold = mediumSeverityThreshold;
        this.lowSeverityThreshold = lowSeverityThreshold;
        this.highSeverityScanResult = sastResultsDTO.getHighSeverity();
        this.mediumSeverityScanResult = sastResultsDTO.getMediumSeverity();
        this.lowSeverityScanResult = sastResultsDTO.getLowSeverity();
    }

    public int getHighSeverityThreshold() {
        return highSeverityThreshold;
    }

    public void setHighSeverityThreshold(int highSeverityThreshold) {
        this.highSeverityThreshold = highSeverityThreshold;
    }

    public int getMediumSeverityThreshold() {
        return mediumSeverityThreshold;
    }

    public void setMediumSeverityThreshold(int mediumSeverityThreshold) {
        this.mediumSeverityThreshold = mediumSeverityThreshold;
    }

    public int getLowSeverityThreshold() {
        return lowSeverityThreshold;
    }

    public void setLowSeverityThreshold(int lowSeverityThreshold) {
        this.lowSeverityThreshold = lowSeverityThreshold;
    }

    public int getHighSeverityScanResult() {
        return highSeverityScanResult;
    }

    public void setHighSeverityScanResult(int highSeverityScanResult) {
        this.highSeverityScanResult = highSeverityScanResult;
    }

    public int getMediumSeverityScanResult() {
        return mediumSeverityScanResult;
    }

    public void setMediumSeverityScanResult(int mediumSeverityScanResult) {
        this.mediumSeverityScanResult = mediumSeverityScanResult;
    }

    public int getLowSeverityScanResult() {
        return lowSeverityScanResult;
    }

    public void setLowSeverityScanResult(int lowSeverityScanResult) {
        this.lowSeverityScanResult = lowSeverityScanResult;
    }

    public ScanType getScanType() {
        return scanType;
    }

    public void setScanType(ScanType scanType) {
        this.scanType = scanType;
    }
}
