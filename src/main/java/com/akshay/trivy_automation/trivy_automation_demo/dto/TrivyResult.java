package com.akshay.trivy_automation.trivy_automation_demo.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class TrivyResult {

    @JsonProperty("Target")
    private String target;

    @JsonProperty("Class")
    private String clazz;

    @JsonProperty("Type")
    private String type;

    @JsonProperty("Vulnerabilities")
    private List<TrivyVulnerability> vulnerabilities;
}