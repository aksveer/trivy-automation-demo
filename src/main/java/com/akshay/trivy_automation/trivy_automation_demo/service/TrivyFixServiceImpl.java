package com.akshay.trivy_automation.trivy_automation_demo.service;

import com.akshay.trivy_automation.trivy_automation_demo.dto.TrivyReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.model.io.xpp3.MavenXpp3Writer;
import org.kohsuke.github.GHPullRequest;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;


import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class TrivyFixServiceImpl implements TrivyFixService{

    private static final Set<String> SEVERITIES = Set.of("HIGH", "CRITICAL");
    private static final String BRANCH_NAME = "auto/trivy-maven-fix";
    private static final String PR_TITLE = "chore: fix HIGH & CRITICAL Maven vulnerabilities";
    private static final String PR_BODY =
            "This PR was auto-generated to fix HIGH and CRITICAL Maven vulnerabilities detected by Trivy.";

    @Override
    public String fixAndCreatePR(MultipartFile trivyFile) throws Exception {

        // 1️⃣ Parse Trivy
        ObjectMapper mapper = new ObjectMapper();
        TrivyReport report = mapper.readValue(trivyFile.getInputStream(), TrivyReport.class);

        Map<String, String> fixes = extractFixes(report);
        if (fixes.isEmpty()) {
            return "No fixable vulnerabilities found.";
        }

        // 2️⃣ Update pom.xml
        boolean updated = updatePomFiles(fixes);
        if (!updated) {
            return "No pom.xml updates required.";
        }

        // 3️⃣ Git operations
        git("checkout", "-b", BRANCH_NAME);
        git("add", ".");
        git("commit", "-m", PR_TITLE);
        git("push", "--set-upstream", "origin", BRANCH_NAME);

        // 4️⃣ Create PR
        return createPullRequest();
    }

    private Map<String, String> extractFixes(TrivyReport report) {
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

    private boolean updatePomFiles(Map<String, String> fixes) throws Exception {

        boolean updated = false;

        List<Path> pomFiles = Files.walk(Path.of("."))
                .filter(p -> p.getFileName().toString().equals("pom.xml"))
                .toList();

        for (Path pom : pomFiles) {

            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(new FileReader(pom.toFile()));
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

            if (pomUpdated) {
                MavenXpp3Writer writer = new MavenXpp3Writer();
                writer.write(new FileWriter(pom.toFile()), model);
                updated = true;
            }
        }
        return updated;
    }


    private void git(String... args) throws Exception {
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(Stream.concat(Stream.of("git"), Arrays.stream(args)).toList());
        pb.inheritIO();
        Process p = pb.start();
        if (p.waitFor() != 0) {
            throw new RuntimeException("Git command failed");
        }
    }

    private String createPullRequest() throws IOException {
        String token = System.getenv("GITHUB_TOKEN");
        String repo = System.getenv("GITHUB_REPOSITORY");

        GitHub github = new GitHubBuilder().withOAuthToken(token).build();
        GHRepository repository = github.getRepository(repo);

        GHPullRequest pr = repository.createPullRequest(
                PR_TITLE,
                BRANCH_NAME,
                "main",
                PR_BODY
        );

        return pr.getHtmlUrl().toString();
    }

    private Optional<Dependency> findDirectDependency(
            Model model, String groupId, String artifactId) {

        return model.getDependencies().stream()
                .filter(d -> groupId.equals(d.getGroupId())
                        && artifactId.equals(d.getArtifactId()))
                .findFirst();
    }

    private Optional<Dependency> findManagedDependency(
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

    private void addDependencyManagementOverride(
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

        model.getDependencyManagement().addDependency(dep);
    }
}
