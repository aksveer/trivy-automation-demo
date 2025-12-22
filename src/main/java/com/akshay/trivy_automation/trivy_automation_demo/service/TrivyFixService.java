package com.akshay.trivy_automation.trivy_automation_demo.service;

import com.akshay.trivy_automation.trivy_automation_demo.dto.TrivyReport;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.kohsuke.github.GHRepository;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.Optional;

public interface TrivyFixService {

    String fixAndCreatePR(MultipartFile trivyReport) throws Exception;

    Map<String, String> extractFixes(TrivyReport report);

    String updatePomFiles(GHRepository repository, Map<String, String> fixes) throws Exception;

    Optional<Dependency> findDirectDependency(
            Model model, String groupId, String artifactId);

    Optional<Dependency> findManagedDependency(
            Model model, String groupId, String artifactId);

    boolean addDependencyManagementOverride(
            Model model,
            String groupId,
            String artifactId,
            String fixedVersion,
            boolean updated);
}
