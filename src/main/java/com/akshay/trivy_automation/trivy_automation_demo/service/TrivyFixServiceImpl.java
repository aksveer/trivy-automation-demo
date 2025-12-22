package com.akshay.trivy_automation.trivy_automation_demo.service;

import com.akshay.trivy_automation.trivy_automation_demo.dto.TrivyReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.kohsuke.github.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class TrivyFixServiceImpl implements TrivyFixService {

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

        String updatedPomXml = updatePomFiles(repository, fixes);

        if (updatedPomXml != null) {
            createBranch(repository);
            createCommit(repository, BRANCH_NAME, updatedPomXml);
            boolean prCreated = createPr(repository, BRANCH_NAME);
            return prCreated ? "PR Created" : "PR Not Created";
        }

        return "No fixable vulnerabilities found.";
    }

    @Override
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

    /**
     * Returns updated pom.xml content as a STRING (preserving existing formatting),
     * or null if no changes needed.
     */
    @Override
    public String updatePomFiles(GHRepository repository, Map<String, String> fixes) throws Exception {

        if (token == null || token.isBlank()) {
            throw new IllegalStateException("GITHUB_TOKEN is not set");
        }

        GHContent pomContent;
        try {
            pomContent = repository.getFileContent(POM_XML);
        } catch (GHFileNotFoundException ex) {
            log.info("No pom.xml found");
            return null;
        }

        String originalPomXml = pomContent.getContent();
        String updatedPomXml = originalPomXml;

        MavenXpp3Reader reader = new MavenXpp3Reader();
        Model model = reader.read(new java.io.StringReader(originalPomXml));

        boolean changed = false;

        for (Map.Entry<String, String> entry : fixes.entrySet()) {
            String[] cords = entry.getKey().split(":");
            if (cords.length != 2) continue;

            String groupId = cords[0];
            String artifactId = cords[1];
            String fixedVersion = entry.getValue();

            // 1) Direct dependency
            Optional<Dependency> direct = findDirectDependency(model, groupId, artifactId);
            if (direct.isPresent()) {
                Dependency dep = direct.get();
                if (!fixedVersion.equals(dep.getVersion())) {
                    updatedPomXml = PomXmlPatcher.patchDependencyVersion(updatedPomXml, groupId, artifactId, fixedVersion, false);
                    dep.setVersion(fixedVersion);
                    changed = true;
                }
                continue;
            }

            // 2) dependencyManagement dependency
            Optional<Dependency> managed = findManagedDependency(model, groupId, artifactId);
            if (managed.isPresent()) {
                Dependency dep = managed.get();
                if (!fixedVersion.equals(dep.getVersion())) {
                    updatedPomXml = PomXmlPatcher.patchDependencyVersion(updatedPomXml, groupId, artifactId, fixedVersion, true);
                    dep.setVersion(fixedVersion);
                    changed = true;
                }
                continue;
            }

            // 3) Transitive -> add override into dependencyManagement
            updatedPomXml = PomXmlPatcher.ensureDependencyManagementOverride(updatedPomXml, groupId, artifactId, fixedVersion);
            changed = true;
        }

        if (!changed) return null;
        return updatedPomXml;
    }

    @Override
    public Optional<Dependency> findDirectDependency(Model model, String groupId, String artifactId) {
        return model.getDependencies().stream()
                .filter(d -> groupId.equals(d.getGroupId())
                        && artifactId.equals(d.getArtifactId()))
                .findFirst();
    }

    @Override
    public Optional<Dependency> findManagedDependency(Model model, String groupId, String artifactId) {

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

    @Override
    public boolean addDependencyManagementOverride(
            Model model,
            String groupId,
            String artifactId,
            String fixedVersion,
            boolean updated) {

        if (model.getDependencyManagement() == null) {
            model.setDependencyManagement(new DependencyManagement());
        }

        Dependency dep = new Dependency();
        dep.setGroupId(groupId);
        dep.setArtifactId(artifactId);
        dep.setVersion(fixedVersion);

        model.getDependencyManagement().addDependency(dep);
        return true;
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

    public void createCommit(GHRepository repository, String branchName, String updatedPomXml) throws IOException {

        String currentSha = repository.getFileContent(POM_XML).getSha();

        repository.createContent()
                .branch(branchName)
                .path(POM_XML)
                .content(updatedPomXml)
                .message("Auto-fix Maven vulnerabilities detected by Trivy")
                .sha(currentSha)
                .commit();
    }

    public boolean createPr(GHRepository repository, String branchName) throws IOException {
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
            return true;
        }

        return false;
    }

    /**
     * String patcher that preserves original formatting by only changing the smallest possible substring.
     */
    static final class PomXmlPatcher {

        private PomXmlPatcher() {}

        static String patchDependencyVersion(String pomXml,
                                             String groupId,
                                             String artifactId,
                                             String newVersion,
                                             boolean inDependencyManagement) {

            String scope = inDependencyManagement ? "dependencyManagement" : "dependencies";
            int startScope = locateTagStart(pomXml, scope, 0);
            if (startScope < 0) {
                // If asked to patch managed dependency but no depMgmt exists, fallback to whole doc search.
                startScope = 0;
            }

            int endScope = inDependencyManagement ? locateTagEnd(pomXml, scope, startScope) : pomXml.length();
            if (endScope < 0) endScope = pomXml.length();

            String before = pomXml.substring(0, startScope);
            String scoped = pomXml.substring(startScope, endScope);
            String after = pomXml.substring(endScope);

            String patchedScoped = patchFirstMatchingDependencyBlock(scoped, groupId, artifactId, newVersion);

            return before + patchedScoped + after;
        }

        static String ensureDependencyManagementOverride(String pomXml,
                                                         String groupId,
                                                         String artifactId,
                                                         String version) {

            // If dependencyManagement exists and already contains the dependency, just patch it.
            if (containsDependencyInDependencyManagement(pomXml, groupId, artifactId)) {
                return patchDependencyVersion(pomXml, groupId, artifactId, version, true);
            }

            // If dependencyManagement exists, insert into its <dependencies>...</dependencies>
            int dmStart = locateTagStart(pomXml, "dependencyManagement", 0);
            if (dmStart >= 0) {
                int dmEnd = locateTagEnd(pomXml, "dependencyManagement", dmStart);
                if (dmEnd < 0) dmEnd = pomXml.length();

                String dmBlock = pomXml.substring(dmStart, dmEnd);
                String dmPatched = insertDependencyIntoDependencyManagementBlock(dmBlock, groupId, artifactId, version);

                return pomXml.substring(0, dmStart) + dmPatched + pomXml.substring(dmEnd);
            }

            // If dependencyManagement does not exist, create it and insert before <dependencies> if possible.
            String dmToInsert = buildDependencyManagementBlock(pomXml, groupId, artifactId, version);

            int depsStart = locateTagStart(pomXml, "dependencies", 0);
            if (depsStart >= 0) {
                return pomXml.substring(0, depsStart) + dmToInsert + pomXml.substring(depsStart);
            }

            // Fallback: insert before </project>
            int projectEnd = pomXml.lastIndexOf("</project>");
            if (projectEnd >= 0) {
                return pomXml.substring(0, projectEnd) + dmToInsert + pomXml.substring(projectEnd);
            }

            // If it's not even a normal POM, just append.
            return pomXml + dmToInsert;
        }

        private static boolean containsDependencyInDependencyManagement(String pomXml, String groupId, String artifactId) {
            int dmStart = locateTagStart(pomXml, "dependencyManagement", 0);
            if (dmStart < 0) return false;

            int dmEnd = locateTagEnd(pomXml, "dependencyManagement", dmStart);
            if (dmEnd < 0) dmEnd = pomXml.length();

            String dmBlock = pomXml.substring(dmStart, dmEnd);
            return containsDependency(dmBlock, groupId, artifactId);
        }

        private static boolean containsDependency(String xml, String groupId, String artifactId) {
            String g = Pattern.quote(groupId);
            String a = Pattern.quote(artifactId);

            Pattern p = Pattern.compile(
                    "<dependency\\b[\\s\\S]*?>[\\s\\S]*?<groupId>\\s*" + g + "\\s*</groupId>[\\s\\S]*?<artifactId>\\s*" + a + "\\s*</artifactId>[\\s\\S]*?</dependency>",
                    Pattern.CASE_INSENSITIVE
            );
            return p.matcher(xml).find();
        }

        private static String patchFirstMatchingDependencyBlock(String xml, String groupId, String artifactId, String newVersion) {
            String g = Pattern.quote(groupId);
            String a = Pattern.quote(artifactId);

            Pattern depPattern = Pattern.compile(
                    "(<dependency\\b[\\s\\S]*?>)([\\s\\S]*?)(</dependency>)",
                    Pattern.CASE_INSENSITIVE
            );

            Matcher m = depPattern.matcher(xml);
            StringBuffer out = new StringBuffer();

            while (m.find()) {
                String open = m.group(1);
                String body = m.group(2);
                String close = m.group(3);

                if (!containsTagValue(body, "groupId", groupId) || !containsTagValue(body, "artifactId", artifactId)) {
                    m.appendReplacement(out, Matcher.quoteReplacement(open + body + close));
                    continue;
                }

                // If <version> exists -> replace only the text
                Pattern versionPattern = Pattern.compile("(<version>)(\\s*[\\s\\S]*?\\s*)(</version>)", Pattern.CASE_INSENSITIVE);
                Matcher vm = versionPattern.matcher(body);
                if (vm.find()) {
                    String patchedBody = vm.replaceFirst("$1" + Matcher.quoteReplacement(newVersion) + "$3");
                    m.appendReplacement(out, Matcher.quoteReplacement(open + patchedBody + close));
                    m.appendTail(out);
                    return out.toString();
                }

                // Else: insert <version> after <artifactId>...</artifactId> preserving indentation
                String patchedBody = insertVersionAfterArtifactId(body, newVersion);
                m.appendReplacement(out, Matcher.quoteReplacement(open + patchedBody + close));
                m.appendTail(out);
                return out.toString();
            }

            m.appendTail(out);
            return out.toString();
        }

        private static boolean containsTagValue(String xml, String tag, String expected) {
            String t = Pattern.quote(tag);
            String e = Pattern.quote(expected);
            Pattern p = Pattern.compile("<" + t + ">\\s*" + e + "\\s*</" + t + ">", Pattern.CASE_INSENSITIVE);
            return p.matcher(xml).find();
        }

        private static String insertVersionAfterArtifactId(String dependencyBody, String newVersion) {
            Pattern artifactIdLinePattern = Pattern.compile("(\\r?\\n)([\\t ]*)<artifactId>[^<]*</artifactId>(\\r?\\n)?", Pattern.CASE_INSENSITIVE);
            Matcher am = artifactIdLinePattern.matcher(dependencyBody);

            if (am.find()) {
                String newline = am.group(1);
                String indent = am.group(2);
                String trailingNewline = am.group(3) == null ? "" : am.group(3);

                String versionLine = newline + indent + "<version>" + newVersion + "</version>" + (trailingNewline.isEmpty() ? "" : "");
                int insertPos = am.end(0);
                return dependencyBody.substring(0, insertPos) + versionLine + dependencyBody.substring(insertPos);
            }

            // Fallback: append before end of dependency block with best-effort indentation
            String indent = detectIndentForChild(dependencyBody);
            String nl = dependencyBody.contains("\r\n") ? "\r\n" : "\n";
            return dependencyBody + nl + indent + "<version>" + newVersion + "</version>";
        }

        private static String insertDependencyIntoDependencyManagementBlock(String dmBlock,
                                                                            String groupId,
                                                                            String artifactId,
                                                                            String version) {

            int depsStart = locateTagStart(dmBlock, "dependencies", 0);
            if (depsStart < 0) {
                // If no <dependencies> inside depMgmt, create it right after opening <dependencyManagement>
                int dmOpenEnd = dmBlock.indexOf(">", dmBlock.toLowerCase(Locale.ROOT).indexOf("<dependencymanagement"));
                if (dmOpenEnd < 0) return dmBlock;

                String nl = dmBlock.contains("\r\n") ? "\r\n" : "\n";
                String baseIndent = detectIndentBeforeTag(dmBlock, "<dependencyManagement");
                String childIndent = baseIndent + detectIndentUnit(dmBlock);

                String toInsert =
                        nl + childIndent + "<dependencies>" +
                                nl + childIndent + detectIndentUnit(dmBlock) + buildDependencyBlock(dmBlock, groupId, artifactId, version, childIndent + detectIndentUnit(dmBlock)) +
                                nl + childIndent + "</dependencies>" + nl + baseIndent;

                return dmBlock.substring(0, dmOpenEnd + 1) + toInsert + dmBlock.substring(dmOpenEnd + 1);
            }

            int depsEnd = locateTagEnd(dmBlock, "dependencies", depsStart);
            if (depsEnd < 0) depsEnd = dmBlock.length();

            String depsBlock = dmBlock.substring(depsStart, depsEnd);

            String depIndent = detectIndentInsideDependencies(depsBlock, dmBlock);
            String nl = dmBlock.contains("\r\n") ? "\r\n" : "\n";

            String newDepBlock = buildDependencyBlock(dmBlock, groupId, artifactId, version, depIndent);
            int insertAt = depsBlock.lastIndexOf("</dependencies>");
            if (insertAt < 0) return dmBlock;

            String patchedDepsBlock =
                    depsBlock.substring(0, insertAt) +
                            nl + newDepBlock +
                            depsBlock.substring(insertAt);

            return dmBlock.substring(0, depsStart) + patchedDepsBlock + dmBlock.substring(depsEnd);
        }

        private static String buildDependencyManagementBlock(String pomXml,
                                                             String groupId,
                                                             String artifactId,
                                                             String version) {

            String nl = pomXml.contains("\r\n") ? "\r\n" : "\n";
            String baseIndent = detectIndentBeforeTag(pomXml, "<dependencies");
            String indentUnit = detectIndentUnit(pomXml);

            String dmIndent = baseIndent;
            String depsIndent = dmIndent + indentUnit;
            String depIndent = depsIndent + indentUnit;

            String depBlock = buildDependencyBlock(pomXml, groupId, artifactId, version, depIndent);

            return
                    dmIndent + "<dependencyManagement>" + nl +
                            depsIndent + "<dependencies>" + nl +
                            depBlock + nl +
                            depsIndent + "</dependencies>" + nl +
                            dmIndent + "</dependencyManagement>" + nl;
        }

        private static String buildDependencyBlock(String pomXml, String groupId, String artifactId, String version, String indent) {
            String nl = pomXml.contains("\r\n") ? "\r\n" : "\n";
            String indentUnit = detectIndentUnit(pomXml);
            String childIndent = indent + indentUnit;

            return
                    indent + "<dependency>" + nl +
                            childIndent + "<groupId>" + groupId + "</groupId>" + nl +
                            childIndent + "<artifactId>" + artifactId + "</artifactId>" + nl +
                            childIndent + "<version>" + version + "</version>" + nl +
                            indent + "</dependency>";
        }

        private static String detectIndentInsideDependencies(String depsBlock, String fullDoc) {
            // Try to find indentation of an existing <dependency> inside this <dependencies>
            Pattern p = Pattern.compile("(\\r?\\n)([\\t ]*)<dependency\\b", Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(depsBlock);
            if (m.find()) {
                return m.group(2);
            }

            // Otherwise infer from <dependencies> indentation + indent unit
            Pattern depsOpen = Pattern.compile("(\\r?\\n)([\\t ]*)<dependencies\\b", Pattern.CASE_INSENSITIVE);
            Matcher dm = depsOpen.matcher(depsBlock);
            if (dm.find()) {
                return dm.group(2) + detectIndentUnit(fullDoc);
            }

            return detectIndentUnit(fullDoc);
        }

        private static String detectIndentBeforeTag(String xml, String tagPrefix) {
            int idx = xml.toLowerCase(Locale.ROOT).indexOf(tagPrefix.toLowerCase(Locale.ROOT));
            if (idx < 0) return "";
            int lineStart = xml.lastIndexOf('\n', idx);
            if (lineStart < 0) lineStart = 0;
            else lineStart = lineStart + 1;

            int i = lineStart;
            StringBuilder sb = new StringBuilder();
            while (i < xml.length()) {
                char c = xml.charAt(i);
                if (c == ' ' || c == '\t') {
                    sb.append(c);
                    i++;
                } else {
                    break;
                }
            }
            return sb.toString();
        }

        private static String detectIndentUnit(String xml) {
            // If the file uses tabs, prefer tab.
            if (xml.contains("\n\t")) return "\t";

            // Try to detect common 2 or 4 spaces indentation.
            Pattern p = Pattern.compile("\\r?\\n( +)<[^!?/]", Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(xml);
            int best = -1;
            while (m.find()) {
                int len = m.group(1).length();
                if (len > 0 && (best == -1 || len < best)) {
                    best = len;
                }
            }
            if (best > 0) {
                return " ".repeat(best);
            }

            return "  ";
        }

        private static String detectIndentForChild(String xmlFragment) {
            // best effort: if it contains a newline+indent+<groupId>, use that indent
            Pattern p = Pattern.compile("(\\r?\\n)([\\t ]*)<groupId>", Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(xmlFragment);
            if (m.find()) return m.group(2);

            return xmlFragment.contains("\n\t") ? "\t" : "  ";
        }

        private static int locateTagStart(String xml, String tag, int fromIndex) {
            Pattern p = Pattern.compile("<" + Pattern.quote(tag) + "\\b", Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(xml);
            if (m.find(fromIndex)) return m.start();
            return -1;
        }

        private static int locateTagEnd(String xml, String tag, int fromIndex) {
            Pattern p = Pattern.compile("</" + Pattern.quote(tag) + "\\s*>", Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(xml);
            if (m.find(fromIndex)) return m.end();
            return -1;
        }
    }
}