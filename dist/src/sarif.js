import { RULES } from "./rules.js";
function sarifLevel(finding) {
    if (finding.severity === "critical" || finding.severity === "high")
        return "error";
    if (finding.severity === "medium")
        return "warning";
    return "note";
}
export function toSarif(result) {
    const rules = RULES.map((rule) => ({
        id: rule.id,
        name: rule.title.replace(/[^A-Za-z0-9]+/g, "_"),
        shortDescription: { text: rule.title },
        fullDescription: { text: rule.description },
        help: { text: `${rule.description}\n\nRemediation: ${rule.remediation}` },
        properties: { category: rule.category, severity: rule.severity },
    }));
    if (result.findings.some((finding) => finding.ruleId === "AI001")) {
        rules.push({
            id: "AI001",
            name: "Semantic_security_review",
            shortDescription: { text: "Semantic security review finding" },
            fullDescription: { text: "An opt-in OpenAI semantic review identified a risk grounded in scanned agent content." },
            help: { text: "Review the supplied evidence and remediation manually before changing code or configuration." },
            properties: { category: "semantic-review", severity: "medium" },
        });
    }
    return {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [
            {
                tool: {
                    driver: {
                        name: result.tool.name,
                        version: result.tool.version,
                        informationUri: "https://github.com/boxzeemon-beep/agent-risk-linter",
                        rules,
                    },
                },
                automationDetails: { id: "agent-risk-linter/" },
                results: result.findings.map((finding) => ({
                    ruleId: finding.ruleId,
                    level: sarifLevel(finding),
                    message: { text: `${finding.title}: ${finding.description}` },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: { uri: finding.file.replaceAll("\\", "/"), uriBaseId: "%SRCROOT%" },
                                region: {
                                    startLine: finding.line,
                                    startColumn: finding.column,
                                    endLine: finding.endLine,
                                    endColumn: Math.max(finding.endColumn, finding.column + 1),
                                    snippet: finding.excerpt ? { text: finding.excerpt } : undefined,
                                },
                            },
                        },
                    ],
                    partialFingerprints: { primaryLocationLineHash: finding.fingerprint },
                    properties: { severity: finding.severity, category: finding.category, source: finding.source, remediation: finding.remediation },
                })),
            },
        ],
    };
}
//# sourceMappingURL=sarif.js.map