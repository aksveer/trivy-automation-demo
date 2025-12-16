package com.akshay.trivy_automation.trivy_automation_demo.dto;


import lombok.Data;
import java.util.List;

@Data
public class TrivyReport {
    private List<TrivyResult> results;
}