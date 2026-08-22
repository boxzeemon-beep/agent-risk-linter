const PLACEHOLDER_MARKERS = [
    "example",
    "placeholder",
    "redacted",
    "changeme",
    "dummy",
    "sample",
    "your_",
    "your-",
    "xxxxx",
    "<token>",
    "<secret>",
];
function looksLikePlaceholder(value) {
    const lower = value.toLowerCase();
    return value.includes("${") || value.includes("{{") || PLACEHOLDER_MARKERS.some((marker) => lower.includes(marker));
}
function redactSensitiveHeaderAssignments(input) {
    const quoted = /((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)["']?\s*[:=]\s*)(["'])([^\r\n]*?)\2/gi;
    let output = input.replace(quoted, (match, prefix, quote, value) => {
        if (looksLikePlaceholder(value))
            return match;
        return `${prefix}${quote}[REDACTED]${quote}`;
    });
    output = output.replace(/((?:cookie|set-cookie|x-api-key|api-key|x-auth-token)["']?\s*[:=]\s*)(?!["'])([^\s,;#}\]]+)/gi, (match, prefix, value) => {
        if (looksLikePlaceholder(value))
            return match;
        return `${prefix}[REDACTED]`;
    });
    return output;
}
function redactPrivateKeys(input) {
    const headerPattern = /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----/g;
    const parts = [];
    let cursor = 0;
    for (let match = headerPattern.exec(input); match; match = headerPattern.exec(input)) {
        const header = match[0];
        const endMarker = header.replace("BEGIN", "END");
        const endIndex = input.indexOf(endMarker, match.index + header.length);
        parts.push(input.slice(cursor, match.index), "[REDACTED PRIVATE KEY]");
        if (endIndex === -1)
            return parts.join("");
        cursor = endIndex + endMarker.length;
        headerPattern.lastIndex = cursor;
    }
    parts.push(input.slice(cursor));
    return parts.join("");
}
export function redactText(input) {
    let output = redactPrivateKeys(input);
    output = output.replace(/((?:Proxy-)?Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s"']+/gi, "$1[REDACTED]");
    output = redactSensitiveHeaderAssignments(output);
    output = output.replace(/\b(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,})\b/g, "[REDACTED TOKEN]");
    output = output.replace(/((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)["']?\s*[:=]\s*["']?)([^"'\s,;#]{8,})(["']?)/gi, (match, prefix, value, suffix) => {
        if (looksLikePlaceholder(value))
            return match;
        return `${prefix}[REDACTED]${suffix}`;
    });
    return output;
}
export function sanitizeTerminalText(input) {
    return input
        .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
        .replace(/[\u202A-\u202E\u2066-\u2069]/gu, "")
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}
export function redactAndSanitize(input) {
    return sanitizeTerminalText(redactText(input));
}
//# sourceMappingURL=redact.js.map