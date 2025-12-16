package com.akshay.trivy_automation.trivy_automation_demo.controller;

import com.akshay.trivy_automation.trivy_automation_demo.service.TrivyFixService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/trivy")
@RequiredArgsConstructor
public class TrivyFixController {

    private final TrivyFixService fixService;

    @PostMapping("/fix")
    public ResponseEntity<String> fix(@RequestParam("file") MultipartFile file)
            throws Exception {

        return ResponseEntity.ok(fixService.fixAndCreatePR(file));
    }
}
