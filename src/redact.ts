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

function looksLikePlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return value.startsWith("$") || value.startsWith("{{") || PLACEHOLDER_MARKERS.some((marker) => lower.includes(marker));
}

export function redactText(input: string): string {
  let output = input;

  output = output.replace(
    /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----/g,
    "[REDACTED PRIVATE KEY]",
  );
  output = output.replace(/(Authorization\s*:\s*Bearer\s+)[^\s"']+/gi, "$1[REDACTED]");
  output = output.replace(/\b(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,})\b/g, "[REDACTED TOKEN]");
  output = output.replace(
    /((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)["']?\s*[:=]\s*["']?)([^"'\s,;#]{8,})(["']?)/gi,
    (match, prefix: string, value: string, suffix: string) => {
      if (looksLikePlaceholder(value)) return match;
      return `${prefix}[REDACTED]${suffix}`;
    },
  );

  return output;
}

export function sanitizeTerminalText(input: string): string {
  return input
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\u202A-\u202E\u2066-\u2069]/gu, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}

export function redactAndSanitize(input: string): string {
  return sanitizeTerminalText(redactText(input));
}
