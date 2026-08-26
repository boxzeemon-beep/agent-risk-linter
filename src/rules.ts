import path from "node:path";
import type { FileKind, Rule, RuleContext, RuleMatch, Severity } from "./types.js";

type RuleDefinition = Omit<Rule, "detect">;

const ALL_TEXT_KINDS: readonly FileKind[] = ["instruction", "script", "manifest", "workflow", "config", "document"];
const EXECUTABLE_KINDS: readonly FileKind[] = ["instruction", "script", "workflow", "config", "document"];
const CREDENTIAL_PLACEHOLDERS = /(?:example|placeholder|redacted|changeme|dummy|sample|your[_-]|x{4,}|\$\{|\{\{|process\.env|<[^>]*(?:token|secret|key)[^>]*>)/i;
const SENSITIVE_HTTP_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"]);

function cloneGlobal(pattern: RegExp): RegExp {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return new RegExp(pattern.source, flags);
}

function patternRule(definition: RuleDefinition, patterns: readonly RegExp[]): Rule {
  return {
    ...definition,
    detect({ file }: RuleContext): RuleMatch[] {
      const matches: RuleMatch[] = [];
      for (const sourcePattern of patterns) {
        const pattern = cloneGlobal(sourcePattern);
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(file.content)) !== null) {
          matches.push({ index: match.index, length: Math.max(match[0].length, 1) });
          if (match[0].length === 0) pattern.lastIndex += 1;
        }
      }
      return matches;
    },
  };
}

function parsePackageJson(context: RuleContext): Record<string, unknown> | undefined {
  if (path.posix.basename(context.file.relativePath.toLowerCase()) !== "package.json") return undefined;
  try {
    const value: unknown = JSON.parse(context.file.content);
    return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function findKey(content: string, key: string): number {
  const quoted = content.indexOf(`"${key}"`);
  return quoted >= 0 ? quoted : 0;
}

function isCredentialPlaceholder(value: string): boolean {
  const normalized = value.trim();
  return !normalized || CREDENTIAL_PLACEHOLDERS.test(normalized) || /^(?:Bearer\s+)?(?:token|secret|password)$/i.test(normalized);
}

function findClosingBrace(content: string, openIndex: number): number | undefined {
  let depth = 0;
  let quote: "'" | '"' | undefined;
  let escaped = false;

  for (let index = openIndex; index < content.length; index += 1) {
    const character = content[index];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\" && quote === '"') {
        escaped = true;
      } else if (character === quote) {
        quote = undefined;
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === "{") {
      depth += 1;
    } else if (character === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function sensitiveHeaderAssignments(content: string, offset = 0): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const assignment = /(?:^|[,\r\n])\s*["']?([A-Za-z0-9_-]+)["']?\s*[:=]\s*(["'])([^\r\n]*?)\2/gim;
  let match: RegExpExecArray | null;
  while ((match = assignment.exec(content)) !== null) {
    const header = match[1] ?? "";
    const value = match[3] ?? "";
    if (!SENSITIVE_HTTP_HEADERS.has(header.toLowerCase()) || isCredentialPlaceholder(value)) continue;
    const headerOffset = match[0].indexOf(header);
    matches.push({ index: offset + match.index + Math.max(headerOffset, 0), length: header.length, message: `Static credential header: ${header}` });
  }
  return matches;
}

function mcpStaticCredentialHeaderRule(): Rule {
  return {
    id: "MCP004",
    title: "MCP HTTP credential is stored in a static header",
    description: "A reusable credential in MCP http_headers can leak through repository history or reports, and a client that follows a cross-origin redirect could disclose it to another server.",
    remediation: "Revoke any committed value. Prefer OAuth, bearer_token_env_var, or env_http_headers, and use an MCP client that restricts redirects to the configured origin.",
    severity: "high",
    category: "mcp-security",
    appliesTo: ["config", "manifest"],
    detect({ file }): RuleMatch[] {
      const matches: RuleMatch[] = [];

      const inlineMap = /(?:^|[,{]\s*)["']?http_headers["']?\s*[:=]\s*\{/gim;
      let mapMatch: RegExpExecArray | null;
      while ((mapMatch = inlineMap.exec(file.content)) !== null) {
        const openIndex = mapMatch.index + mapMatch[0].lastIndexOf("{");
        const closeIndex = findClosingBrace(file.content, openIndex);
        if (closeIndex === undefined) break;
        matches.push(...sensitiveHeaderAssignments(file.content.slice(openIndex + 1, closeIndex), openIndex + 1));
        inlineMap.lastIndex = closeIndex + 1;
      }

      const tablePattern = /^\s*\[([^\]\r\n]+)\]\s*(?:#.*)?$/gim;
      const tables: Array<{ name: string; start: number; contentStart: number }> = [];
      let tableMatch: RegExpExecArray | null;
      while ((tableMatch = tablePattern.exec(file.content)) !== null) {
        tables.push({ name: (tableMatch[1] ?? "").trim().toLowerCase(), start: tableMatch.index, contentStart: tablePattern.lastIndex });
      }
      for (let index = 0; index < tables.length; index += 1) {
        const table = tables[index];
        if (!table || !/(?:^|\.)http_headers$/.test(table.name)) continue;
        const end = tables[index + 1]?.start ?? file.content.length;
        matches.push(...sensitiveHeaderAssignments(file.content.slice(table.contentStart, end), table.contentStart));
      }

      const dottedHeader = /^\s*["']?http_headers["']?\.["']?([A-Za-z0-9_-]+)["']?\s*=\s*(["'])([^\r\n]*?)\2/gim;
      let dottedMatch: RegExpExecArray | null;
      while ((dottedMatch = dottedHeader.exec(file.content)) !== null) {
        const header = dottedMatch[1] ?? "";
        const value = dottedMatch[3] ?? "";
        if (!SENSITIVE_HTTP_HEADERS.has(header.toLowerCase()) || isCredentialPlaceholder(value)) continue;
        const headerOffset = dottedMatch[0].indexOf(header);
        matches.push({ index: dottedMatch.index + Math.max(headerOffset, 0), length: header.length, message: `Static credential header: ${header}` });
      }

      const seen = new Set<number>();
      return matches.filter((match) => {
        if (seen.has(match.index)) return false;
        seen.add(match.index);
        return true;
      });
    },
  };
}

function packageInstallHookRule(): Rule {
  return {
    id: "SC001",
    title: "Package lifecycle install hook",
    description: "Install-time lifecycle hooks execute automatically during dependency installation and are a common supply-chain execution point.",
    remediation: "Remove the hook when possible. Otherwise keep it minimal, vendor-reviewed, tested, and documented; never download and execute remote code from it.",
    severity: "high",
    category: "supply-chain",
    appliesTo: ["manifest"],
    detect(context): RuleMatch[] {
      const packageJson = parsePackageJson(context);
      if (!packageJson) return [];
      const scripts = packageJson.scripts;
      if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) return [];
      return ["preinstall", "install", "postinstall"]
        .filter((hook) => typeof (scripts as Record<string, unknown>)[hook] === "string")
        .map((hook) => ({ index: findKey(context.file.content, hook), length: hook.length + 2, message: `Lifecycle hook: ${hook}` }));
    },
  };
}

function remoteDependencyRule(): Rule {
  return {
    id: "SC002",
    title: "Dependency bypasses a package registry version",
    description: "Git, URL, and remote archive dependencies can bypass normal registry integrity and version controls.",
    remediation: "Prefer a registry release pinned by the lockfile. If a remote dependency is necessary, pin an immutable commit and verify its provenance.",
    severity: "medium",
    category: "supply-chain",
    appliesTo: ["manifest"],
    detect(context): RuleMatch[] {
      const packageJson = parsePackageJson(context);
      if (!packageJson) return [];
      const matches: RuleMatch[] = [];
      for (const sectionName of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const section = packageJson[sectionName];
        if (typeof section !== "object" || section === null || Array.isArray(section)) continue;
        for (const [name, specifier] of Object.entries(section as Record<string, unknown>)) {
          if (typeof specifier !== "string" || !/^(?:https?:|git(?:\+|:)|github:)/i.test(specifier)) continue;
          const index = context.file.content.indexOf(specifier);
          matches.push({ index: Math.max(index, findKey(context.file.content, name)), length: specifier.length, message: `${name}: ${specifier}` });
        }
      }
      return matches;
    },
  };
}

function unpinnedActionRule(): Rule {
  return {
    id: "SC003",
    title: "GitHub Action is not pinned to a full commit SHA",
    description: "Mutable action tags and branches can change after review, creating a CI supply-chain risk.",
    remediation: "Pin third-party actions to a reviewed 40-character commit SHA and use an update bot to propose controlled upgrades.",
    severity: "high",
    category: "supply-chain",
    appliesTo: ["workflow"],
    detect({ file }): RuleMatch[] {
      const matches: RuleMatch[] = [];
      const pattern = /^\s*-?\s*uses:\s*["']?([^@\s"']+)@([^#\s"']+)/gim;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(file.content)) !== null) {
        const action = match[1] ?? "";
        const reference = match[2] ?? "";
        if (action.startsWith("./") || action.startsWith("docker://") || /^[a-f0-9]{40}$/i.test(reference)) continue;
        matches.push({ index: match.index, length: match[0].length, message: `${action}@${reference}` });
      }
      return matches;
    },
  };
}

function hardcodedCredentialRule(): Rule {
  const assignment = /\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)["']?\s*[:=]\s*["']?([^"'\s,;#]{12,})["']?/gim;
  const placeholders = /(?:example|placeholder|redacted|changeme|dummy|sample|your[_-]|x{4,}|\$\{|process\.env)/i;
  const privateKey = /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----/g;

  return {
    id: "CRED003",
    title: "Possible hardcoded credential",
    description: "A credential-like value or private key appears directly in a scanned file.",
    remediation: "Revoke exposed credentials, remove them from history, and load secrets from a scoped secret store or environment variable.",
    severity: "critical",
    category: "credentials",
    appliesTo: ALL_TEXT_KINDS,
    detect({ file }): RuleMatch[] {
      const matches: RuleMatch[] = [];
      let match: RegExpExecArray | null;
      const pattern = cloneGlobal(assignment);
      while ((match = pattern.exec(file.content)) !== null) {
        const value = match[2] ?? "";
        if (!placeholders.test(value)) matches.push({ index: match.index, length: match[0].length });
      }
      const keyPattern = cloneGlobal(privateKey);
      while ((match = keyPattern.exec(file.content)) !== null) {
        matches.push({ index: match.index, length: match[0].length });
      }
      return matches;
    },
  };
}

function workflowCombinationRule(): Rule {
  return {
    id: "CI003",
    title: "Privileged workflow checks out untrusted pull-request code",
    description: "A pull_request_target workflow appears to reference the contributor-controlled head revision, which can expose write tokens or secrets to untrusted code.",
    remediation: "Do not execute or check out PR head code in pull_request_target. Split untrusted testing from privileged follow-up workflows and pass only reviewed artifacts.",
    severity: "critical",
    category: "ci-security",
    appliesTo: ["workflow"],
    detect({ file }): RuleMatch[] {
      const event = /\bpull_request_target\b/i.exec(file.content);
      const untrustedHead = /github\.event\.pull_request\.(?:head\.sha|head\.ref|head\.repo)/i.exec(file.content);
      if (!event || !untrustedHead) return [];
      return [{ index: event.index, length: event[0].length }];
    },
  };
}

function skillMetadataRule(): Rule {
  return {
    id: "META001",
    title: "Skill metadata is missing required fields",
    description: "A SKILL.md file without clear name and description metadata is harder to identify and can trigger unpredictably.",
    remediation: "Add YAML frontmatter containing only a concise name and an explicit description of when the skill should run.",
    severity: "low",
    category: "skill-metadata",
    appliesTo: ["instruction"],
    detect({ file }): RuleMatch[] {
      if (path.posix.basename(file.relativePath).toLowerCase() !== "skill.md") return [];
      const frontmatter = /^---\s*\r?\n([\s\S]*?)\r?\n---/.exec(file.content);
      if (!frontmatter) return [{ index: 0, length: Math.min(file.content.length, 1) }];
      const body = frontmatter[1] ?? "";
      if (!/^name:\s*\S+/im.test(body) || !/^description:\s*\S+/im.test(body)) {
        return [{ index: 0, length: frontmatter[0].length }];
      }
      return [];
    },
  };
}

export const RULES: readonly Rule[] = [
  patternRule(
    {
      id: "AGENT001",
      title: "Instruction attempts to override a higher-trust boundary",
      description: "The text tells an agent to ignore or override prior, system, developer, safety, or security instructions.",
      remediation: "Remove the override. State the intended task without changing the agent's instruction hierarchy or safety policy.",
      severity: "high",
      category: "prompt-injection",
      appliesTo: ["instruction", "document", "config"],
    },
    [/\b(?:ignore|disregard|override|bypass)\b[^\r\n]{0,80}\b(?:previous|prior|system|developer|higher[- ]priority|safety|security)\b[^\r\n]{0,80}\b(?:instruction|message|rule|policy|prompt)s?\b/gi],
  ),
  patternRule(
    {
      id: "AGENT002",
      title: "Instruction requests concealment",
      description: "The text asks the agent not to reveal, report, log, or mention an instruction or action.",
      remediation: "Remove concealment requirements. Security-relevant actions must remain visible and auditable to the user.",
      severity: "high",
      category: "prompt-injection",
      appliesTo: ["instruction", "document", "config"],
    },
    [/\b(?:do not|don't|never)\b[^\r\n]{0,60}\b(?:mention|disclose|reveal|report|show|log)\b[^\r\n]{0,60}\b(?:this|these|instruction|action|command)s?\b/gi],
  ),
  patternRule(
    {
      id: "AGENT003",
      title: "Instruction attempts to bypass approval or sandboxing",
      description: "The text directs an agent to skip an approval, permission check, sandbox, review, or other security boundary.",
      remediation: "Preserve host approvals and sandbox boundaries. Narrow the requested operation and require explicit authorization for sensitive actions.",
      severity: "critical",
      category: "authorization",
      appliesTo: ["instruction", "document", "config"],
    },
    [/\b(?:skip|bypass|disable|avoid|silence)\b[^\r\n]{0,70}\b(?:approval|confirmation|sandbox|permission|security check|human review|review gate)s?\b/gi],
  ),
  patternRule(
    {
      id: "AGENT004",
      title: "Instruction delegates authority to untrusted content",
      description: "The text tells an agent to execute or obey commands found in issues, comments, webpages, downloads, or other externally controlled content.",
      remediation: "Treat external content as data. Extract facts from it, but never grant it instruction authority or execute referenced code without review.",
      severity: "high",
      category: "prompt-injection",
      appliesTo: ["instruction", "document"],
    },
    [/\b(?:execute|follow|obey|run)\b[^\r\n]{0,80}\b(?:instruction|command|script)s?\b[^\r\n]{0,50}\b(?:issue|pull request|comment|webpage|download|external|remote|user[- ]supplied)\b/gi],
  ),
  patternRule(
    {
      id: "SHELL001",
      title: "Remote content is piped directly into a shell",
      description: "Downloading and executing a script in one pipeline prevents meaningful review and turns network or DNS compromise into code execution.",
      remediation: "Download to a temporary file, verify an immutable checksum or signature, inspect it, and execute only after explicit approval.",
      severity: "critical",
      category: "command-execution",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/(?:\bcurl\b|\bwget\b)[^\r\n|]{0,240}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|pwsh|powershell)\b/gi, /(?:bash|sh|zsh)\s*<\([^\r\n]{0,40}(?:curl|wget)\b/gi],
  ),
  patternRule(
    {
      id: "SHELL002",
      title: "PowerShell expression or encoded command execution",
      description: "Invoke-Expression and encoded commands obscure the executed payload and are frequently abused by malicious automation.",
      remediation: "Call a reviewed executable with an argument array. Avoid dynamic expressions and encoded command payloads.",
      severity: "high",
      category: "command-execution",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/\b(?:Invoke-Expression|iex)\b/gi, /-(?:EncodedCommand|enc)\b/gi],
  ),
  patternRule(
    {
      id: "SHELL003",
      title: "Dynamic command execution",
      description: "Dynamic shell or language evaluation can turn untrusted strings into executable code.",
      remediation: "Use direct process spawning with a fixed executable and an argument array; validate every variable that crosses the command boundary.",
      severity: "high",
      category: "command-execution",
      appliesTo: ["instruction", "script", "workflow", "config"],
    },
    [/\b(?:eval|exec)\s*\(/gi, /\b(?:child_process\.)?exec(?:Sync)?\s*\(/gi, /\bos\.system\s*\(/gi, /\bshell\s*[:=]\s*true\b/gi],
  ),
  patternRule(
    {
      id: "FS001",
      title: "Destructive deletion targets a filesystem root or home directory",
      description: "The command can recursively remove a root, drive, or user home directory.",
      remediation: "Resolve and verify an explicit project-scoped target, reject roots and home directories, and prefer a recoverable trash operation.",
      severity: "critical",
      category: "filesystem",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\s+(?:--\s+)?(?:\/(?:\*|\s|$)|~(?:\/\*|\s|$)|\$HOME(?:\/\*|\s|$)|\$\{HOME\}(?:\/\*|\s|$))/gim, /\bRemove-Item\b[^\r\n]{0,120}\b-Recurse\b[^\r\n]{0,120}\b(?:[A-Za-z]:\\|\$HOME|\$env:USERPROFILE)\b/gi],
  ),
  patternRule(
    {
      id: "FS002",
      title: "Broad recursive deletion",
      description: "A forceful recursive delete is present and may destroy more data than intended if its target is wrong or attacker-controlled.",
      remediation: "Use a literal, project-scoped path; resolve it before deletion; reject broad targets; and log or preview the exact files affected.",
      severity: "high",
      category: "filesystem",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\b/gi, /\bRemove-Item\b[^\r\n]{0,160}\b-Recurse\b[^\r\n]{0,160}\b-Force\b/gi, /\brd\s+\/s\s+\/q\b/gi],
  ),
  patternRule(
    {
      id: "CRED001",
      title: "Sensitive credential store is accessed",
      description: "The instruction or script references SSH keys, cloud credentials, Git credential stores, keychains, or a non-example environment file.",
      remediation: "Request only the minimum named secret through a scoped secret mechanism. Never enumerate or upload a user's credential stores.",
      severity: "high",
      category: "credentials",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/(?:~\/\.ssh|\.aws\/credentials|\.git-credentials|\bid_(?:rsa|ed25519)\b|\bkeychain\b|(?<![A-Za-z0-9_])\.env\b(?!\.(?:example|sample)))/gi],
  ),
  patternRule(
    {
      id: "CRED002",
      title: "Environment variables are enumerated",
      description: "Dumping the process environment can expose API keys and CI secrets to logs or downstream commands.",
      remediation: "Read only explicitly named variables and ensure secret values are never logged.",
      severity: "medium",
      category: "credentials",
      appliesTo: EXECUTABLE_KINDS,
    },
    [
      /^\s*(?:env|printenv)\s*(?:[|;&]|$)/gim,
      /\bGet-ChildItem\s+Env:/gi,
      /\bObject\.(?:keys|values|entries)\s*\(\s*process\.env\s*\)/gi,
      /\b(?:JSON\.stringify|console\.(?:log|dir))\s*\(\s*process\.env\s*\)/gi,
      /\{\s*\.\.\.\s*process\.env\s*\}/gi,
    ],
  ),
  hardcodedCredentialRule(),
  patternRule(
    {
      id: "NET001",
      title: "Network request may transmit credentials",
      description: "A network command references tokens, secrets, authorization data, environment files, or credential stores.",
      remediation: "Remove secret data from the request. Allowlist the destination, send only the minimum fields, and require explicit user consent.",
      severity: "critical",
      category: "network-egress",
      appliesTo: EXECUTABLE_KINDS,
    },
    [
      /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n]{0,260}(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|\.env|credentials|Authorization)/gi,
      /(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|\.env|credentials|Authorization)[^\r\n]{0,260}\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b/gi,
      /^\s*(?:env|printenv)\s*\|\s*(?:curl|wget)\b/gim,
    ],
  ),
  patternRule(
    {
      id: "NET002",
      title: "Possible reverse shell or interactive remote command channel",
      description: "The command pattern can create an interactive shell over a network connection.",
      remediation: "Remove the command. Use an authenticated, audited remote administration channel with least privilege instead.",
      severity: "critical",
      category: "network-egress",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/\/dev\/tcp\//gi, /\bnc\b[^\r\n]{0,80}\s-e\s/gi, /\bbash\s+-i\b[^\r\n]{0,80}>&/gi, /System\.Net\.Sockets\.TCPClient/gi],
  ),
  patternRule(
    {
      id: "OBF001",
      title: "Encoded content is decoded for execution",
      description: "Decoding an opaque payload immediately before evaluation or shell execution hides the behavior from review.",
      remediation: "Store reviewed source as plain text, verify its provenance, and invoke it without an eval or shell pipeline.",
      severity: "high",
      category: "obfuscation",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/\bbase64\b[^\r\n]{0,100}(?:--decode|-d)[^\r\n]{0,100}\|\s*(?:sh|bash|zsh)/gi, /\bFromBase64String\b[^\r\n]{0,180}\b(?:Invoke-Expression|iex)\b/gi, /\beval\b[^\r\n]{0,180}\bbase64\b/gi],
  ),
  patternRule(
    {
      id: "OBF002",
      title: "Bidirectional text control character",
      description: "Bidirectional formatting controls can reorder displayed text and conceal the apparent meaning of instructions or code.",
      remediation: "Remove the control character and use ordinary visible text. If mixed-direction text is required, isolate it in reviewed documentation rather than executable instructions.",
      severity: "medium",
      category: "obfuscation",
      appliesTo: ALL_TEXT_KINDS,
    },
    [/[\u202A-\u202E\u2066-\u2069]/gu],
  ),
  patternRule(
    {
      id: "PRIV001",
      title: "Command broadens privileges or file permissions",
      description: "The command requests elevated privileges or world-writable permissions.",
      remediation: "Run with the least privilege required. Prefer narrowly scoped ownership and permission changes over sudo or mode 777.",
      severity: "medium",
      category: "privilege",
      appliesTo: EXECUTABLE_KINDS,
    },
    [/\bsudo\s+/gi, /\bchmod\s+(?:-R\s+)?777\b/gi],
  ),
  packageInstallHookRule(),
  remoteDependencyRule(),
  unpinnedActionRule(),
  patternRule(
    {
      id: "CI001",
      title: "Workflow grants write-all permissions",
      description: "write-all gives every available GitHub token scope write access and increases the impact of workflow compromise.",
      remediation: "Set top-level permissions to read-all or {}, then grant only the specific write permission required at the job level.",
      severity: "high",
      category: "ci-security",
      appliesTo: ["workflow"],
    },
    [/^\s*permissions:\s*write-all\s*$/gim],
  ),
  patternRule(
    {
      id: "CI002",
      title: "Workflow uses pull_request_target",
      description: "pull_request_target runs in the base repository context and may receive write permissions or secrets while processing untrusted pull-request metadata.",
      remediation: "Use pull_request for untrusted tests. If pull_request_target is required, never execute PR code and keep permissions minimal.",
      severity: "high",
      category: "ci-security",
      appliesTo: ["workflow"],
    },
    [/\bpull_request_target\b/gi],
  ),
  workflowCombinationRule(),
  patternRule(
    {
      id: "MCP001",
      title: "MCP endpoint uses unencrypted HTTP",
      description: "A remote MCP endpoint over plain HTTP can expose prompts, tool data, credentials, or tool results in transit.",
      remediation: "Use HTTPS with certificate validation. Plain HTTP is acceptable only for an explicitly local loopback endpoint.",
      severity: "high",
      category: "mcp-security",
      appliesTo: ["config"],
    },
    [/http:\/\/(?!(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/))[^\s"']+/gi],
  ),
  patternRule(
    {
      id: "MCP002",
      title: "MCP server is launched through a shell wrapper",
      description: "Using sh, bash, cmd, or PowerShell with a command string creates an avoidable injection boundary in MCP server startup.",
      remediation: "Configure the executable directly and pass each argument as a separate fixed array element.",
      severity: "high",
      category: "mcp-security",
      appliesTo: ["config"],
    },
    [/"command"\s*:\s*"(?:sh|bash|zsh|cmd|powershell|pwsh)"[\s\S]{0,260}"(?:-c|\/c|Command)"/gi],
  ),
  patternRule(
    {
      id: "MCP003",
      title: "Codex lifecycle hook invokes an MCP tool",
      description: "An MCP tool hook can run automatically during the Codex lifecycle and can template prompt or tool-event data into a tool call that may access files, networks, credentials, or code execution.",
      remediation: "Review the exact event, matcher, server, tool, and input template. Remove unnecessary hooks, restrict MCP permissions and credentials, and avoid forwarding sensitive or untrusted event fields.",
      severity: "medium",
      category: "mcp-security",
      appliesTo: ["config", "manifest"],
    },
    [/"type"\s*:\s*"mcp_tool"/gi, /^\s*type\s*=\s*["']mcp_tool["']\s*(?:#.*)?$/gim],
  ),
  mcpStaticCredentialHeaderRule(),
  patternRule(
    {
      id: "WEB001",
      title: "Website registers an agent-callable WebMCP tool",
      description:
        "WebMCP exposes page capabilities to agents in the live signed-in session. Tool names, annotations, and results are untrusted and do not prove that a handler is read-only.",
      remediation:
        "Review the handler and called application logic. Keep input schemas narrow, describe side effects accurately, enforce existing authentication, authorization, and input validation, and return only data needed to verify the action.",
      severity: "medium",
      category: "webmcp-security",
      appliesTo: ["script"],
    },
    [/\bdocument\s*\.\s*modelContext\s*(?:\?\.\s*|\.\s*)registerTool\s*\(/gi],
  ),
  skillMetadataRule(),
];

export function getRule(ruleId: string): Rule | undefined {
  return RULES.find((rule) => rule.id.toLowerCase() === ruleId.toLowerCase());
}

export function isSeverity(value: string): value is Severity {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}
