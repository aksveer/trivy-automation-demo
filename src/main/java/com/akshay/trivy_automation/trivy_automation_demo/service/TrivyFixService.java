package com.akshay.trivy_automation.trivy_automation_demo.service;

import com.akshay.trivy_automation.trivy_automation_demo.dto.TrivyReport;
import org.springframework.web.multipart.MultipartFile;

public interface TrivyFixService {

    public String fixAndCreatePR(MultipartFile trivyReport) throws Exception;
}
