package com.akshay.trivy_automation.trivy_automation_demo.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class TrivyReport {

    @JsonProperty("Results")
    private List<TrivyResult> Results;
}