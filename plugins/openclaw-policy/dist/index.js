import { createHash } from "node:crypto";
const DEFAULT_SIDECAR_URL = "http://127.0.0.1:47838";
const DEFAULT_ARGUMENT_LENGTH = 512;
const secretPatterns = [
    {
        kind: "private_key",
        pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    },
    { kind: "oauth_token", pattern: /Bearer\s+[A-Za-z0-9._~+/=-]{16,}/g },
    { kind: "api_key", pattern: /sk-[A-Za-z0-9_-]{16,}/g },
    { kind: "aws_access_key", pattern: /\bA(KIA|SIA)[A-Z0-9]{16}\b/g },
    { kind: "slack_token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
    { kind: "stripe_key", pattern: /\b[rs]k_(live|test)_[A-Za-z0-9]{16,}\b/g },
    { kind: "github_token", pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
    { kind: "npm_token", pattern: /\bnpm_[A-Za-z0-9]{20,}\b/g },
    { kind: "pypi_token", pattern: /\bpypi-[A-Za-z0-9_-]{32,}\b/g },
    {
        kind: "jwt",
        pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b/g,
    },
    { kind: "oauth_token", pattern: /ya29\.[A-Za-z0-9._-]{16,}/g },
    { kind: "oauth_token", pattern: /ghp_[A-Za-z0-9_]{16,}/g },
    {
        kind: "session_cookie",
        pattern: /(session|cookie)[_-]?(token|secret)?["'=:\s]+[A-Za-z0-9._~+/=-]{20,}/gi,
    },
    { kind: "database_url", pattern: /(postgres|mysql|mongodb):\/\/[^\s"']+/gi },
];
export function packageIdentity() {
    return {
        name: "@runbrake/openclaw-policy",
        phase: "sidecar-shadow-policy",
    };
}
export function toToolCallEvent(input, options = {}) {
    const observedAt = input.observedAt ?? (options.now ?? new Date()).toISOString();
    const event = {
        id: input.id ??
            stableEventId([
                input.agentId,
                input.userId,
                input.skill,
                input.tool,
                observedAt,
            ]),
        agentId: input.agentId,
        userId: input.userId,
        skill: input.skill,
        tool: input.tool,
        phase: input.phase ?? "before",
        observedAt,
        payloadClassifications: [...(input.payloadClassifications ?? [])],
        destinationDomains: [...(input.destinationDomains ?? [])],
    };
    if (input.organizationId) {
        event.organizationId = input.organizationId;
    }
    if (input.environment) {
        event.environment = input.environment;
    }
    if (options.includeArguments !== false && input.arguments) {
        event.arguments = summarizeArguments(input.arguments, options.maxArgumentLength ?? DEFAULT_ARGUMENT_LENGTH);
    }
    return event;
}
export function toInstallEvent(input, options = {}) {
    const observedAt = input.observedAt ?? (options.now ?? new Date()).toISOString();
    const kind = normalizeInstallKind(input.kind ?? input.type ?? input.packageType);
    const event = {
        id: input.id ??
            input.installId ??
            stableEventId([
                kind,
                input.name ?? "",
                input.source ?? "",
                input.artifactPath ?? input.path ?? input.localPath ?? "",
                observedAt,
            ]),
        kind,
        observedAt,
    };
    assignIfPresent(event, "name", input.name);
    assignIfPresent(event, "version", input.version);
    assignIfPresent(event, "source", input.source);
    assignIfPresent(event, "artifactPath", input.artifactPath ?? input.path ?? input.localPath);
    assignIfPresent(event, "artifactHash", input.artifactHash);
    assignIfPresent(event, "organizationId", input.organizationId ?? options.organizationId);
    assignIfPresent(event, "agentId", input.agentId ?? options.agentId);
    assignIfPresent(event, "userId", input.userId ?? options.userId);
    const findings = input.openclawFindings ?? input.builtInFindings ?? [];
    if (findings.length > 0) {
        event.openclawFindings = findings.map((finding) => truncate(redactSecretValue(String(finding)), DEFAULT_ARGUMENT_LENGTH));
    }
    return event;
}
export function toRuntimeObservation(input, options = {}) {
    const observedAt = input.observedAt ?? (options.now ?? new Date()).toISOString();
    const argumentEvidence = summarizeArguments(input.arguments ?? {}, options.maxArgumentLength ?? DEFAULT_ARGUMENT_LENGTH);
    const argumentKeys = Object.keys(argumentEvidence).sort();
    const observation = {
        id: input.id ??
            stableEventId([
                "runtime",
                input.agentId,
                input.skill ?? "",
                input.tool,
                observedAt,
            ]),
        source: input.source ?? "openclaw.before_tool_call",
        agentId: input.agentId,
        tool: input.tool,
        phase: input.phase ?? "before",
        observedAt,
        destinationDomains: [...(input.destinationDomains ?? [])],
        payloadClassifications: [...(input.payloadClassifications ?? [])],
        argumentKeys,
        argumentEvidence,
    };
    assignIfPresent(observation, "organizationId", input.organizationId);
    assignIfPresent(observation, "userId", input.userId);
    assignIfPresent(observation, "skill", input.skill);
    assignIfPresent(observation, "environment", input.environment);
    return observation;
}
export async function requestPolicyDecision(event, options = {}) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const decidedAt = (options.now ?? new Date()).toISOString();
    if (!fetchImpl) {
        return failOpenDecision(event, decidedAt, "fetch is unavailable");
    }
    try {
        const response = await fetchImpl(`${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/v1/policy/decision`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(event),
        });
        if (!response.ok) {
            return failOpenDecision(event, decidedAt, `sidecar returned HTTP ${response.status}: ${await response.text()}`);
        }
        const payload = (await response.json());
        if (!payload.decision) {
            return failOpenDecision(event, decidedAt, "sidecar response was missing a decision");
        }
        return payload;
    }
    catch (error) {
        return failOpenDecision(event, decidedAt, `sidecar unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
}
export async function requestInstallDecision(event, options = {}) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const decidedAt = (options.now ?? new Date()).toISOString();
    if (!fetchImpl) {
        return failOpenInstallDecision(event, decidedAt, "fetch is unavailable");
    }
    try {
        const response = await fetchImpl(`${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/v1/install/decision`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(event),
        });
        if (!response.ok) {
            return failOpenInstallDecision(event, decidedAt, `sidecar returned HTTP ${response.status}: ${await response.text()}`);
        }
        const payload = (await response.json());
        if (!payload.decision) {
            return failOpenInstallDecision(event, decidedAt, "sidecar response was missing a decision");
        }
        return payload;
    }
    catch (error) {
        return failOpenInstallDecision(event, decidedAt, `sidecar unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
}
export async function requestRuntimeObservation(observation, options = {}) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (!fetchImpl) {
        return undefined;
    }
    try {
        const response = await fetchImpl(`${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/v1/runtime/observation`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(observation),
        });
        if (!response.ok) {
            await response.text();
            return undefined;
        }
        return (await response.json());
    }
    catch {
        return undefined;
    }
}
export async function createStartupReceipt(options = {}) {
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    const observedAt = (options.now ?? new Date()).toISOString();
    let receipt;
    if (!fetchImpl) {
        receipt = startupReceipt("fail_open", observedAt, "fetch is unavailable");
        await emitReceiptNotice(receipt, options);
        return receipt;
    }
    try {
        const response = await fetchImpl(`${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/healthz`, {
            method: "GET",
            headers: { accept: "application/json" },
            body: "",
        });
        if (!response.ok) {
            receipt = startupReceipt("fail_open", observedAt, `sidecar returned HTTP ${response.status}: ${await response.text()}`);
        }
        else {
            receipt = startupReceipt("active", observedAt, "sidecar connected - policy checks visible in this session");
        }
    }
    catch (error) {
        receipt = startupReceipt("fail_open", observedAt, `sidecar unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
    await emitReceiptNotice(receipt, options);
    return receipt;
}
export function decisionToBeforeToolCallResult(decision) {
    if (decision.action !== "deny" &&
        decision.action !== "quarantine" &&
        decision.action !== "kill_switch") {
        return undefined;
    }
    return {
        block: true,
        blockReason: `RunBrake blocked ${decision.policyId}: ${decision.reasons[0] ?? decision.action}`,
    };
}
export function decisionToBeforeInstallResult(decision) {
    if (decision.action !== "deny" &&
        decision.action !== "quarantine" &&
        decision.action !== "kill_switch") {
        return undefined;
    }
    return {
        block: true,
        blockReason: `RunBrake blocked install ${decision.policyId}: ${decision.reasons[0] ?? decision.action}`,
    };
}
export function createBeforeToolCallHandler(options = {}) {
    return async (event, context) => {
        const toolCallEvent = toToolCallEvent({
            id: event.toolCallId ?? event.runId,
            organizationId: options.organizationId,
            agentId: context.agentId ?? options.agentId ?? "openclaw-agent",
            userId: options.userId ??
                context.sessionKey ??
                context.sessionId ??
                "openclaw-user",
            skill: options.skill ?? "openclaw-runtime",
            tool: event.toolName,
            environment: options.environment,
            arguments: event.params ?? {},
            payloadClassifications: options.payloadClassifications ?? [],
            destinationDomains: options.destinationDomains ?? [],
        }, options);
        if (options.recordRuntimeObservations !== false) {
            const observationResponse = await requestRuntimeObservation(toRuntimeObservation({
                id: toolCallEvent.id,
                organizationId: toolCallEvent.organizationId,
                agentId: toolCallEvent.agentId,
                userId: toolCallEvent.userId,
                skill: toolCallEvent.skill,
                tool: toolCallEvent.tool,
                phase: toolCallEvent.phase,
                observedAt: toolCallEvent.observedAt,
                environment: toolCallEvent.environment,
                arguments: event.params ?? {},
                payloadClassifications: toolCallEvent.payloadClassifications,
                destinationDomains: toolCallEvent.destinationDomains,
            }, options), options);
            await emitReceiptNotice(observationResponse?.receipt, options);
        }
        const response = await requestPolicyDecision(toolCallEvent, options);
        await emitReceiptNotice(response.receipt, options);
        return decisionToBeforeToolCallResult(response.decision);
    };
}
export function createBeforeInstallHandler(options = {}) {
    return async (event, context) => {
        const installEvent = toInstallEvent(openClawInstallEventToInput(event), {
            ...options,
            agentId: context.agentId ?? options.agentId ?? "openclaw-agent",
            userId: options.userId ??
                context.sessionKey ??
                context.sessionId ??
                "openclaw-user",
        });
        const response = await requestInstallDecision(installEvent, options);
        await emitReceiptNotice(response.receipt, options);
        return decisionToBeforeInstallResult(response.decision);
    };
}
export function registerRunBrakePluginHooks(api, options = {}) {
    api.on("before_install", createBeforeInstallHandler(options), {
        priority: options.priority ?? 100,
    });
    api.on("before_tool_call", createBeforeToolCallHandler(options), {
        priority: options.priority ?? 100,
    });
}
export const runbrakeOpenClawPolicyPlugin = {
    id: "runbrake-policy",
    name: "RunBrake Policy",
    description: "Evaluates OpenClaw tool calls against a local RunBrake sidecar.",
    register(api) {
        registerRunBrakePluginHooks(api);
    },
};
export default runbrakeOpenClawPolicyPlugin;
async function emitReceiptNotice(receipt, options) {
    if (!receipt || !options.noticeSink || !shouldEmitReceipt(receipt, options)) {
        return;
    }
    await options.noticeSink(receiptToNotice(receipt));
}
function shouldEmitReceipt(receipt, options) {
    const verbosity = options.receiptVerbosity ?? "quiet";
    if (verbosity === "off") {
        return false;
    }
    if (verbosity === "all") {
        return true;
    }
    if (receipt.surface === "startup") {
        return true;
    }
    return (receipt.status === "shadowed" ||
        receipt.status === "redacted" ||
        receipt.status === "approval_required" ||
        receipt.status === "blocked" ||
        receipt.status === "quarantined" ||
        receipt.status === "kill_switch" ||
        receipt.status === "fail_open");
}
function receiptToNotice(receipt) {
    const policySuffix = receipt.policyId ? ` - ${receipt.policyId}` : "";
    return {
        id: stableEventId(["notice", receipt.id, receipt.status]),
        receiptId: receipt.id,
        channel: "agent_session",
        level: noticeLevel(receipt),
        message: `${receipt.headline} - ${receipt.status}${policySuffix}`,
    };
}
function noticeLevel(receipt) {
    if (receipt.severity === "critical" ||
        receipt.status === "blocked" ||
        receipt.status === "quarantined" ||
        receipt.status === "kill_switch") {
        return "critical";
    }
    if (receipt.severity === "high" ||
        receipt.severity === "medium" ||
        receipt.status === "shadowed" ||
        receipt.status === "approval_required" ||
        receipt.status === "fail_open") {
        return "warning";
    }
    return "info";
}
function startupReceipt(status, observedAt, detail) {
    return {
        id: stableEventId(["receipt", "startup", status, observedAt]),
        eventId: `startup-${observedAt}`,
        surface: "startup",
        ecosystem: "openclaw",
        status,
        severity: status === "active" ? "info" : "high",
        headline: status === "active" ? "RunBrake active" : "RunBrake not enforcing",
        detail,
        policyId: status === "fail_open" ? "policy-sidecar-unavailable" : undefined,
        ruleIds: [],
        observedAt,
    };
}
function failOpenReceipt(eventId, surface, subject, observedAt, detail) {
    return {
        id: stableEventId(["receipt", surface, eventId, "fail_open", observedAt]),
        eventId,
        surface,
        ecosystem: "openclaw",
        status: "fail_open",
        severity: "high",
        headline: `RunBrake not enforcing ${subject}`,
        detail,
        policyId: "policy-sidecar-unavailable",
        ruleIds: [],
        observedAt,
    };
}
function summarizeArguments(args, maxArgumentLength) {
    const out = {};
    for (const [key, value] of Object.entries(args).sort(([a], [b]) => a.localeCompare(b))) {
        out[key] = truncate(redactSecretValue(stringifyValue(value)), maxArgumentLength);
    }
    return out;
}
function stringifyValue(value) {
    if (typeof value === "string") {
        return value;
    }
    if (typeof value === "number" ||
        typeof value === "boolean" ||
        value == null) {
        return String(value);
    }
    return JSON.stringify(value);
}
function redactSecretValue(value) {
    let redacted = value;
    for (const { kind, pattern } of secretPatterns) {
        redacted = redacted.replace(pattern, (match) => redactionMarker(kind, match));
    }
    return redacted;
}
function truncate(value, maxLength) {
    if (value.length <= maxLength) {
        return value;
    }
    return `${value.slice(0, Math.max(0, maxLength - 15))}[TRUNCATED]`;
}
function failOpenDecision(event, decidedAt, reason) {
    const decision = {
        id: `decision-fail-open-${event.id}`,
        eventId: event.id,
        policyId: "policy-sidecar-unavailable",
        action: "shadow",
        decidedAt,
        reasons: [reason, "fail-open shadow decision returned locally"],
        redactions: [],
        failMode: "open",
    };
    return {
        decision,
        receipt: failOpenReceipt(event.id, "runtime", event.tool, decidedAt, reason),
    };
}
function failOpenInstallDecision(event, decidedAt, reason) {
    const decision = {
        id: `decision-fail-open-${event.id}`,
        eventId: event.id,
        policyId: "policy-sidecar-unavailable",
        action: "shadow",
        decidedAt,
        reasons: [reason, "fail-open install shadow decision returned locally"],
        redactions: [],
        failMode: "open",
    };
    return {
        decision,
        receipt: failOpenReceipt(event.id, "install", event.name ?? event.source ?? event.id, decidedAt, reason),
    };
}
function normalizeInstallKind(kind) {
    const normalized = (kind ?? "skill").toLowerCase().trim();
    if (normalized === "plugin" || normalized === "plugins") {
        return "plugin";
    }
    return "skill";
}
function openClawInstallEventToInput(event) {
    const kind = event.kind ?? event.type ?? event.packageType ?? event.targetType;
    const normalizedKind = normalizeInstallKind(kind);
    const pluginName = event.plugin?.pluginId ??
        event.plugin?.manifestId ??
        event.plugin?.packageName;
    const skillName = event.skill?.installId;
    return {
        id: event.id ?? event.installId,
        installId: event.installId,
        kind,
        name: event.name ??
            event.targetName ??
            (normalizedKind === "plugin" ? pluginName : skillName),
        version: event.version ?? event.plugin?.version,
        source: event.source ??
            event.request?.requestedSpecifier ??
            event.origin ??
            event.sourcePath,
        artifactPath: event.artifactPath ?? event.path ?? event.localPath ?? event.sourcePath,
        artifactHash: event.artifactHash,
        openclawFindings: event.openclawFindings ??
            event.builtInFindings ??
            summarizeOpenClawBuiltinScan(event.builtinScan),
    };
}
function summarizeOpenClawBuiltinScan(scan) {
    if (!scan) {
        return [];
    }
    const findings = (scan.findings ?? [])
        .map((finding) => {
        const severity = finding.severity?.trim();
        const message = finding.message?.trim() ??
            finding.title?.trim() ??
            finding.ruleId?.trim();
        if (!message) {
            return undefined;
        }
        const location = finding.file
            ? ` (${finding.file}${finding.line ? `:${finding.line}` : ""})`
            : "";
        return `${severity ? `${severity}: ` : ""}${message}${location}`;
    })
        .filter((finding) => Boolean(finding));
    if (findings.length > 0) {
        return findings;
    }
    if (scan.status === "error" && scan.error) {
        return [`scan error: ${scan.error}`];
    }
    return [];
}
function assignIfPresent(target, key, value) {
    if (value !== undefined && value !== "") {
        target[key] = value;
    }
}
function stableEventId(parts) {
    return `event-${hash(parts.join("\0")).slice(0, 16)}`;
}
function redactionMarker(kind, raw) {
    return `[REDACTED:${kind}:${hash(raw).slice(0, 8)}]`;
}
function hash(value) {
    return createHash("sha256").update(value).digest("hex");
}
//# sourceMappingURL=index.js.map