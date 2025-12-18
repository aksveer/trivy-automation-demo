package com.akshay.trivy_automation.trivy_automation_demo.service;

import com.akshay.trivy_automation.trivy_automation_demo.dto.TrivyReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.model.io.xpp3.MavenXpp3Writer;
import org.kohsuke.github.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;


import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

@Slf4j
@Service
public class TrivyFixServiceImpl implements TrivyFixService{

    private static final Set<String> SEVERITIES = Set.of("HIGH", "CRITICAL");
    private static final String BRANCH_NAME = "auto/trivy-maven-fix";
    private static final String PR_TITLE = "chore: fix HIGH & CRITICAL Maven vulnerabilities";
    private static final String PR_BODY =
            "This PR was auto-generated to fix HIGH and CRITICAL Maven vulnerabilities detected by Trivy.";
    public static final String POM_XML = "pom.xml";

    private final String owner;

    private final String repoName;

    private final String token;

    public TrivyFixServiceImpl(@Value("${app.repository.owner}") String owner,
                               @Value("${app.repository.name}") String repoName,
                               @Value("${app.github.token}") String token) {
        this.owner = owner;
        this.repoName = repoName;
        this.token = token;
    }

    @Override
    public String fixAndCreatePR(MultipartFile trivyFile) throws Exception {

        // 1️⃣ Parse Trivy
        ObjectMapper mapper = new ObjectMapper();
        TrivyReport report = mapper.readValue(trivyFile.getInputStream(), TrivyReport.class);

        Map<String, String> fixes = extractFixes(report);
        if (fixes.isEmpty()) {
            return "No fixable vulnerabilities found.";
        }

        GitHub github = new GitHubBuilder()
                .withOAuthToken(token)
                .build();

        GHRepository repository = github.getRepository(owner + "/" + repoName);

        // 2️⃣ Update pom.xml
        Model updated = updatePomFiles(repository, fixes);

        createBranch(repository);
        createCommit(repository, BRANCH_NAME, updated);
        boolean prCreated = createPr(repository, BRANCH_NAME);
        if (prCreated) {
            return "PR Created";
        } else {
            return "PR Not Created";
        }
    }


    public Map<String, String> extractFixes(TrivyReport report) {
        Map<String, String> fixes = new HashMap<>();

        report.getResults().forEach(r -> {
            if (r.getVulnerabilities() == null) return;

            r.getVulnerabilities().stream()
                    .filter(v -> "maven".equalsIgnoreCase(v.getPkgType()))
                    .filter(v -> SEVERITIES.contains(v.getSeverity()))
                    .filter(v -> v.getFixedVersion() != null)
                    .forEach(v -> fixes.put(v.getPkgPath(), v.getFixedVersion()));
        });

        return fixes;
    }

    public Model updatePomFiles(GHRepository repository, Map<String, String> fixes) throws Exception {

        boolean updated = false;

        if (token == null || token.isBlank()) {
            throw new IllegalStateException("GITHUB_TOKEN is not set");
        }


        GHContent pomContent = null;
        try {
            pomContent = repository.getFileContent(POM_XML);
        } catch (GHFileNotFoundException ex) {
            log.info("No pom.xml found");
        }

        MavenXpp3Reader reader = new MavenXpp3Reader();
        String pomXml = pomContent.getContent(); // This is the full content of pom.xml
        Model model = reader.read(new java.io.StringReader(pomXml));
        boolean pomUpdated = false;

        for (Map.Entry<String, String> entry : fixes.entrySet()) {

            String[] cords = entry.getKey().split(":");
            if (cords.length != 2) continue;

            String groupId = cords[0];
            String artifactId = cords[1];
            String fixedVersion = entry.getValue();

            // 1️⃣ Direct dependency
            Optional<Dependency> direct = findDirectDependency(model, groupId, artifactId);
            if (direct.isPresent()) {
                if (!fixedVersion.equals(direct.get().getVersion())) {
                    direct.get().setVersion(fixedVersion);
                    pomUpdated = true;
                }
                continue;
            }

            // 2️⃣ dependencyManagement entry
            Optional<Dependency> managed = findManagedDependency(model, groupId, artifactId);
            if (managed.isPresent()) {
                if (!fixedVersion.equals(managed.get().getVersion())) {
                    managed.get().setVersion(fixedVersion);
                    pomUpdated = true;
                }
                continue;
            }

            // 3️⃣ Transitive → dependencyManagement override
            addDependencyManagementOverride(model, groupId, artifactId, fixedVersion);
            pomUpdated = true;
        }
        return model;
    }

    public Optional<Dependency> findDirectDependency(
            Model model, String groupId, String artifactId) {

        return model.getDependencies().stream()
                .filter(d -> groupId.equals(d.getGroupId())
                        && artifactId.equals(d.getArtifactId()))
                .findFirst();
    }

    public Optional<Dependency> findManagedDependency(
            Model model, String groupId, String artifactId) {

        if (model.getDependencyManagement() == null) {
            return Optional.empty();
        }

        return model.getDependencyManagement()
                .getDependencies()
                .stream()
                .filter(d -> groupId.equals(d.getGroupId())
                        && artifactId.equals(d.getArtifactId()))
                .findFirst();
    }

    public void addDependencyManagementOverride(
            Model model,
            String groupId,
            String artifactId,
            String fixedVersion) {

        if (model.getDependencyManagement() == null) {
            model.setDependencyManagement(new DependencyManagement());
        }

        Dependency dep = new Dependency();
        dep.setGroupId(groupId);
        dep.setArtifactId(artifactId);
        dep.setVersion(fixedVersion);

        if (model.getDependencyManagement() != null) {
            model.getDependencyManagement().addDependency(dep);
        } else {
            model.setDependencyManagement(new DependencyManagement());
            model.getDependencyManagement().addDependency(dep);
        }
    }

    public void createBranch(GHRepository repository) throws IOException {
        String baseBranch = repository.getDefaultBranch();
        String baseSha = repository.getRef("refs/heads/" + baseBranch)
                .getObject()
                .getSha();

        try {
            repository.getRef("refs/heads/" + BRANCH_NAME);
        } catch (GHFileNotFoundException ex) {
            repository.createRef("refs/heads/" + BRANCH_NAME, baseSha);
        }
    }

    public void createCommit(GHRepository repository, String branchName, Model updatedPom) throws IOException {
        java.io.StringWriter sw = new java.io.StringWriter();
        MavenXpp3Writer writer = new MavenXpp3Writer();
        try {
            writer.write(sw, updatedPom);
        } catch (Exception e) {
            throw new IOException("Failed to serialize updated pom.xml", e);
        }
        String updatedXml = sw.toString();

        // Get current file SHA to update in place
        String currentSha = repository.getFileContent(POM_XML).getSha();
        repository.createContent()
                .branch(branchName)
                .path(POM_XML)
                .content(updatedXml)
                .message("Auto-fix Maven vulnerabilities detected by Trivy")
                .sha(repository.getFileContent(POM_XML).getSha())
                .commit();
    }

    public boolean createPr(GHRepository repository, String branchName) throws IOException {
        boolean prCreated = false;
        boolean prExists = !repository.queryPullRequests()
                .state(GHIssueState.OPEN)
                .head(owner + ":" + branchName)
                .list()
                .toList()
                .isEmpty();

        if (!prExists) {
            repository.createPullRequest(
                    PR_TITLE,
                    branchName,
                    "master",
                    PR_BODY
            );
            prCreated = true;
        }

        return prCreated;
    }
}
