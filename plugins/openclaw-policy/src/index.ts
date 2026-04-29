import { createHash } from "node:crypto";

import type {
  AuditEvent,
  InstallEvent,
  PolicyDecision,
  RuntimeObservation,
  ToolCallEvent,
} from "@runbrake/contracts";

export type PackageIdentity = {
  name: string;
  phase: "sidecar-shadow-policy";
};

export type ToolCallInput = {
  id?: string;
  organizationId?: string;
  agentId: string;
  userId: string;
  skill: string;
  tool: string;
  phase?: "before" | "after";
  observedAt?: string;
  environment?: string;
  arguments?: Record<string, unknown>;
  payloadClassifications?: string[];
  destinationDomains?: string[];
};

export type ToolCallEventOptions = {
  now?: Date;
  includeArguments?: boolean;
  maxArgumentLength?: number;
};

export type InstallInput = {
  id?: string;
  installId?: string;
  kind?: string;
  type?: string;
  packageType?: string;
  name?: string;
  version?: string;
  source?: string;
  artifactPath?: string;
  path?: string;
  localPath?: string;
  artifactHash?: string;
  organizationId?: string;
  agentId?: string;
  userId?: string;
  observedAt?: string;
  openclawFindings?: string[];
  builtInFindings?: string[];
  rawPackage?: unknown;
};

export type InstallEventOptions = {
  now?: Date;
  organizationId?: string;
  agentId?: string;
  userId?: string;
};

export type RuntimeObservationInput = {
  id?: string;
  source?: string;
  organizationId?: string;
  agentId: string;
  userId?: string;
  skill?: string;
  tool: string;
  phase?: "before" | "after";
  observedAt?: string;
  environment?: string;
  arguments?: Record<string, unknown>;
  payloadClassifications?: string[];
  destinationDomains?: string[];
};

export type RuntimeObservationOptions = {
  now?: Date;
  maxArgumentLength?: number;
};

export type SidecarDecisionResponse = {
  decision: PolicyDecision;
  auditEvent?: AuditEvent;
};

export type SidecarRuntimeObservationResponse = {
  observation?: RuntimeObservation;
  auditEvent?: AuditEvent;
};

export type FetchLike = (
  url: string,
  init: {
    method: "POST";
    headers: Record<string, string>;
    body: string;
  },
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
}>;

export type SidecarClientOptions = {
  sidecarUrl?: string;
  fetchImpl?: FetchLike;
  now?: Date;
};

export type OpenClawBeforeToolCallEvent = {
  toolName: string;
  params?: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
};

export type OpenClawBeforeInstallEvent = {
  installId?: string;
  id?: string;
  kind?: string;
  type?: string;
  packageType?: string;
  targetType?: string;
  targetName?: string;
  name?: string;
  version?: string;
  source?: string;
  sourcePath?: string;
  sourcePathKind?: string;
  origin?: string;
  request?: {
    kind?: string;
    mode?: string;
    requestedSpecifier?: string;
  };
  builtinScan?: {
    status?: string;
    scannedFiles?: number;
    critical?: number;
    warn?: number;
    info?: number;
    error?: string;
    findings?: Array<{
      severity?: string;
      message?: string;
      title?: string;
      ruleId?: string;
      file?: string;
      line?: number;
    }>;
  };
  skill?: {
    installId?: string;
    installSpec?: unknown;
  };
  plugin?: {
    contentType?: string;
    pluginId?: string;
    packageName?: string;
    manifestId?: string;
    version?: string;
    extensions?: string[];
  };
  artifactPath?: string;
  path?: string;
  localPath?: string;
  artifactHash?: string;
  openclawFindings?: string[];
  builtInFindings?: string[];
  rawPackage?: unknown;
};

export type OpenClawHookContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
};

export type BeforeToolCallResult = {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
  requireApproval?: {
    title: string;
    description: string;
    severity?: "info" | "warning" | "critical";
    timeoutMs?: number;
    timeoutBehavior?: "allow" | "deny";
    pluginId?: string;
  };
};

export type OpenClawBeforeToolCallHandler = (
  event: OpenClawBeforeToolCallEvent,
  context: OpenClawHookContext,
) => Promise<BeforeToolCallResult | undefined>;

export type BeforeInstallResult = {
  block?: boolean;
  blockReason?: string;
};

export type OpenClawBeforeInstallHandler = (
  event: OpenClawBeforeInstallEvent,
  context: OpenClawHookContext,
) => Promise<BeforeInstallResult | undefined>;

export type OpenClawPluginApi = {
  on(
    hookName: "before_tool_call",
    handler: OpenClawBeforeToolCallHandler,
    options?: { priority?: number },
  ): void;
  on(
    hookName: "before_install",
    handler: OpenClawBeforeInstallHandler,
    options?: { priority?: number },
  ): void;
};

export type BeforeToolCallHandlerOptions = SidecarClientOptions &
  ToolCallEventOptions & {
    organizationId?: string;
    agentId?: string;
    userId?: string;
    skill?: string;
    environment?: string;
    destinationDomains?: string[];
    payloadClassifications?: string[];
    priority?: number;
    recordRuntimeObservations?: boolean;
  };

export type BeforeInstallHandlerOptions = SidecarClientOptions &
  InstallEventOptions & {
    priority?: number;
  };

const DEFAULT_SIDECAR_URL = "http://127.0.0.1:47838";
const DEFAULT_ARGUMENT_LENGTH = 512;

const secretPatterns: Array<{ kind: string; pattern: RegExp }> = [
  {
    kind: "private_key",
    pattern:
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
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
    pattern:
      /(session|cookie)[_-]?(token|secret)?["'=:\s]+[A-Za-z0-9._~+/=-]{20,}/gi,
  },
  { kind: "database_url", pattern: /(postgres|mysql|mongodb):\/\/[^\s"']+/gi },
];

export function packageIdentity(): PackageIdentity {
  return {
    name: "@runbrake/openclaw-policy",
    phase: "sidecar-shadow-policy",
  };
}

export function toToolCallEvent(
  input: ToolCallInput,
  options: ToolCallEventOptions = {},
): ToolCallEvent {
  const observedAt =
    input.observedAt ?? (options.now ?? new Date()).toISOString();
  const event: ToolCallEvent = {
    id:
      input.id ??
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
    event.arguments = summarizeArguments(
      input.arguments,
      options.maxArgumentLength ?? DEFAULT_ARGUMENT_LENGTH,
    );
  }

  return event;
}

export function toInstallEvent(
  input: InstallInput,
  options: InstallEventOptions = {},
): InstallEvent {
  const observedAt =
    input.observedAt ?? (options.now ?? new Date()).toISOString();
  const kind = normalizeInstallKind(
    input.kind ?? input.type ?? input.packageType,
  );
  const event: InstallEvent = {
    id:
      input.id ??
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
  assignIfPresent(
    event,
    "artifactPath",
    input.artifactPath ?? input.path ?? input.localPath,
  );
  assignIfPresent(event, "artifactHash", input.artifactHash);
  assignIfPresent(
    event,
    "organizationId",
    input.organizationId ?? options.organizationId,
  );
  assignIfPresent(event, "agentId", input.agentId ?? options.agentId);
  assignIfPresent(event, "userId", input.userId ?? options.userId);

  const findings = input.openclawFindings ?? input.builtInFindings ?? [];
  if (findings.length > 0) {
    event.openclawFindings = findings.map((finding) =>
      truncate(redactSecretValue(String(finding)), DEFAULT_ARGUMENT_LENGTH),
    );
  }

  return event;
}

export function toRuntimeObservation(
  input: RuntimeObservationInput,
  options: RuntimeObservationOptions = {},
): RuntimeObservation {
  const observedAt =
    input.observedAt ?? (options.now ?? new Date()).toISOString();
  const argumentEvidence = summarizeArguments(
    input.arguments ?? {},
    options.maxArgumentLength ?? DEFAULT_ARGUMENT_LENGTH,
  );
  const argumentKeys = Object.keys(argumentEvidence).sort();
  const observation: RuntimeObservation = {
    id:
      input.id ??
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

export async function requestPolicyDecision(
  event: ToolCallEvent,
  options: SidecarClientOptions = {},
): Promise<SidecarDecisionResponse> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const decidedAt = (options.now ?? new Date()).toISOString();
  if (!fetchImpl) {
    return failOpenDecision(event, decidedAt, "fetch is unavailable");
  }

  try {
    const response = await fetchImpl(
      `${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/v1/policy/decision`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(event),
      },
    );
    if (!response.ok) {
      return failOpenDecision(
        event,
        decidedAt,
        `sidecar returned HTTP ${response.status}: ${await response.text()}`,
      );
    }

    const payload = (await response.json()) as SidecarDecisionResponse;
    if (!payload.decision) {
      return failOpenDecision(
        event,
        decidedAt,
        "sidecar response was missing a decision",
      );
    }
    return payload;
  } catch (error) {
    return failOpenDecision(
      event,
      decidedAt,
      `sidecar unavailable: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function requestInstallDecision(
  event: InstallEvent,
  options: SidecarClientOptions = {},
): Promise<SidecarDecisionResponse> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const decidedAt = (options.now ?? new Date()).toISOString();
  if (!fetchImpl) {
    return failOpenInstallDecision(event, decidedAt, "fetch is unavailable");
  }

  try {
    const response = await fetchImpl(
      `${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/v1/install/decision`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(event),
      },
    );
    if (!response.ok) {
      return failOpenInstallDecision(
        event,
        decidedAt,
        `sidecar returned HTTP ${response.status}: ${await response.text()}`,
      );
    }

    const payload = (await response.json()) as SidecarDecisionResponse;
    if (!payload.decision) {
      return failOpenInstallDecision(
        event,
        decidedAt,
        "sidecar response was missing a decision",
      );
    }
    return payload;
  } catch (error) {
    return failOpenInstallDecision(
      event,
      decidedAt,
      `sidecar unavailable: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function requestRuntimeObservation(
  observation: RuntimeObservation,
  options: SidecarClientOptions = {},
): Promise<SidecarRuntimeObservationResponse | undefined> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (!fetchImpl) {
    return undefined;
  }

  try {
    const response = await fetchImpl(
      `${options.sidecarUrl ?? DEFAULT_SIDECAR_URL}/v1/runtime/observation`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(observation),
      },
    );
    if (!response.ok) {
      await response.text();
      return undefined;
    }
    return (await response.json()) as SidecarRuntimeObservationResponse;
  } catch {
    return undefined;
  }
}

export function decisionToBeforeToolCallResult(
  decision: PolicyDecision,
): BeforeToolCallResult | undefined {
  if (
    decision.action !== "deny" &&
    decision.action !== "quarantine" &&
    decision.action !== "kill_switch"
  ) {
    return undefined;
  }

  return {
    block: true,
    blockReason: `RunBrake blocked ${decision.policyId}: ${decision.reasons[0] ?? decision.action}`,
  };
}

export function decisionToBeforeInstallResult(
  decision: PolicyDecision,
): BeforeInstallResult | undefined {
  if (
    decision.action !== "deny" &&
    decision.action !== "quarantine" &&
    decision.action !== "kill_switch"
  ) {
    return undefined;
  }

  return {
    block: true,
    blockReason: `RunBrake blocked install ${decision.policyId}: ${decision.reasons[0] ?? decision.action}`,
  };
}

export function createBeforeToolCallHandler(
  options: BeforeToolCallHandlerOptions = {},
): OpenClawBeforeToolCallHandler {
  return async (event, context) => {
    const toolCallEvent = toToolCallEvent(
      {
        id: event.toolCallId ?? event.runId,
        organizationId: options.organizationId,
        agentId: context.agentId ?? options.agentId ?? "openclaw-agent",
        userId:
          options.userId ??
          context.sessionKey ??
          context.sessionId ??
          "openclaw-user",
        skill: options.skill ?? "openclaw-runtime",
        tool: event.toolName,
        environment: options.environment,
        arguments: event.params ?? {},
        payloadClassifications: options.payloadClassifications ?? [],
        destinationDomains: options.destinationDomains ?? [],
      },
      options,
    );
    if (options.recordRuntimeObservations !== false) {
      await requestRuntimeObservation(
        toRuntimeObservation(
          {
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
          },
          options,
        ),
        options,
      );
    }
    const response = await requestPolicyDecision(toolCallEvent, options);
    return decisionToBeforeToolCallResult(response.decision);
  };
}

export function createBeforeInstallHandler(
  options: BeforeInstallHandlerOptions = {},
): OpenClawBeforeInstallHandler {
  return async (event, context) => {
    const installEvent = toInstallEvent(openClawInstallEventToInput(event), {
      ...options,
      agentId: context.agentId ?? options.agentId ?? "openclaw-agent",
      userId:
        options.userId ??
        context.sessionKey ??
        context.sessionId ??
        "openclaw-user",
    });
    const response = await requestInstallDecision(installEvent, options);
    return decisionToBeforeInstallResult(response.decision);
  };
}

export function registerRunBrakePluginHooks(
  api: OpenClawPluginApi,
  options: BeforeToolCallHandlerOptions & BeforeInstallHandlerOptions = {},
): void {
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
  description:
    "Evaluates OpenClaw tool calls against a local RunBrake sidecar.",
  register(api: OpenClawPluginApi) {
    registerRunBrakePluginHooks(api);
  },
};

export default runbrakeOpenClawPolicyPlugin;

function summarizeArguments(
  args: Record<string, unknown>,
  maxArgumentLength: number,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(args).sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    out[key] = truncate(
      redactSecretValue(stringifyValue(value)),
      maxArgumentLength,
    );
  }
  return out;
}

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    value == null
  ) {
    return String(value);
  }
  return JSON.stringify(value);
}

function redactSecretValue(value: string): string {
  let redacted = value;
  for (const { kind, pattern } of secretPatterns) {
    redacted = redacted.replace(pattern, (match) =>
      redactionMarker(kind, match),
    );
  }
  return redacted;
}

function truncate(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maxLength - 15))}[TRUNCATED]`;
}

function failOpenDecision(
  event: ToolCallEvent,
  decidedAt: string,
  reason: string,
): SidecarDecisionResponse {
  return {
    decision: {
      id: `decision-fail-open-${event.id}`,
      eventId: event.id,
      policyId: "policy-sidecar-unavailable",
      action: "shadow",
      decidedAt,
      reasons: [reason, "fail-open shadow decision returned locally"],
      redactions: [],
      failMode: "open",
    },
  };
}

function failOpenInstallDecision(
  event: InstallEvent,
  decidedAt: string,
  reason: string,
): SidecarDecisionResponse {
  return {
    decision: {
      id: `decision-fail-open-${event.id}`,
      eventId: event.id,
      policyId: "policy-sidecar-unavailable",
      action: "shadow",
      decidedAt,
      reasons: [reason, "fail-open install shadow decision returned locally"],
      redactions: [],
      failMode: "open",
    },
  };
}

function normalizeInstallKind(kind: string | undefined): "skill" | "plugin" {
  const normalized = (kind ?? "skill").toLowerCase().trim();
  if (normalized === "plugin" || normalized === "plugins") {
    return "plugin";
  }
  return "skill";
}

function openClawInstallEventToInput(
  event: OpenClawBeforeInstallEvent,
): InstallInput {
  const kind =
    event.kind ?? event.type ?? event.packageType ?? event.targetType;
  const normalizedKind = normalizeInstallKind(kind);
  const pluginName =
    event.plugin?.pluginId ??
    event.plugin?.manifestId ??
    event.plugin?.packageName;
  const skillName = event.skill?.installId;

  return {
    id: event.id ?? event.installId,
    installId: event.installId,
    kind,
    name:
      event.name ??
      event.targetName ??
      (normalizedKind === "plugin" ? pluginName : skillName),
    version: event.version ?? event.plugin?.version,
    source:
      event.source ??
      event.request?.requestedSpecifier ??
      event.origin ??
      event.sourcePath,
    artifactPath:
      event.artifactPath ?? event.path ?? event.localPath ?? event.sourcePath,
    artifactHash: event.artifactHash,
    openclawFindings:
      event.openclawFindings ??
      event.builtInFindings ??
      summarizeOpenClawBuiltinScan(event.builtinScan),
  };
}

function summarizeOpenClawBuiltinScan(
  scan: OpenClawBeforeInstallEvent["builtinScan"],
): string[] {
  if (!scan) {
    return [];
  }

  const findings = (scan.findings ?? [])
    .map((finding) => {
      const severity = finding.severity?.trim();
      const message =
        finding.message?.trim() ??
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
    .filter((finding): finding is string => Boolean(finding));

  if (findings.length > 0) {
    return findings;
  }
  if (scan.status === "error" && scan.error) {
    return [`scan error: ${scan.error}`];
  }
  return [];
}

function assignIfPresent<T extends Record<string, unknown>, K extends keyof T>(
  target: T,
  key: K,
  value: T[K] | undefined,
): void {
  if (value !== undefined && value !== "") {
    target[key] = value;
  }
}

function stableEventId(parts: string[]): string {
  return `event-${hash(parts.join("\0")).slice(0, 16)}`;
}

function redactionMarker(kind: string, raw: string): string {
  return `[REDACTED:${kind}:${hash(raw).slice(0, 8)}]`;
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
