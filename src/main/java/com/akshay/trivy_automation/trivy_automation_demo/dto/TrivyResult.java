package com.akshay.trivy_automation.trivy_automation_demo.dto;

import lombok.Data;
import java.util.List;

@Data
public class TrivyResult {
    private String type;
    private List<TrivyVulnerability> vulnerabilities;
}