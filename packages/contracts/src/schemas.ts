export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  id: string;
  ruleId: string;
  severity: Severity;
  confidence: number;
  title: string;
  evidence: string[];
  remediation: string;
};

export type ScanReport = {
  id: string;
  agentId: string;
  scannerVersion: string;
  generatedAt: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: Finding[];
  artifactHashes: string[];
};

export type ToolCallEvent = {
  id: string;
  organizationId?: string;
  agentId: string;
  userId: string;
  skill: string;
  tool: string;
  phase: "before" | "after";
  observedAt: string;
  environment?: string;
  arguments?: Record<string, string>;
  payloadClassifications: string[];
  destinationDomains: string[];
};

export type InstallEvent = {
  id: string;
  kind: "skill" | "plugin";
  name?: string;
  version?: string;
  source?: string;
  artifactPath?: string;
  artifactHash?: string;
  organizationId?: string;
  agentId?: string;
  userId?: string;
  observedAt: string;
  openclawFindings?: string[];
};

export type PolicyDecision = {
  id: string;
  eventId: string;
  policyId: string;
  action:
    | "allow"
    | "deny"
    | "redact"
    | "approve"
    | "shadow"
    | "quarantine"
    | "kill_switch";
  decidedAt: string;
  reasons: string[];
  redactions: string[];
  failMode: "open" | "closed";
};

export type ApprovalRequest = {
  id: string;
  eventId: string;
  policyDecisionId: string;
  organizationId: string;
  status: "pending" | "approved" | "denied" | "expired" | "canceled";
  requestedAt: string;
  expiresAt: string;
  approvers: string[];
  evidenceHash: string;
};

export type AuditEvent = {
  id: string;
  organizationId: string;
  agentId: string;
  eventType: string;
  occurredAt: string;
  actor: string;
  subject: string;
  evidenceHash: string;
  previousHash: string | null;
  signature: string;
};

const timestampSchema = {
  type: "string",
  minLength: 20,
} as const;

const stringArraySchema = {
  type: "array",
  items: { type: "string", minLength: 1 },
} as const;

const stringRecordSchema = {
  type: "object",
  additionalProperties: { type: "string" },
} as const;

export const findingSchema = {
  $id: "https://runbrake.dev/schemas/finding.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "ruleId",
    "severity",
    "confidence",
    "title",
    "evidence",
    "remediation",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    ruleId: { type: "string", pattern: "^RB-[A-Z0-9-]+$" },
    severity: {
      type: "string",
      enum: ["critical", "high", "medium", "low", "info"],
    },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    title: { type: "string", minLength: 1 },
    evidence: stringArraySchema,
    remediation: { type: "string", minLength: 1 },
  },
} as const;

export const scanReportSchema = {
  $id: "https://runbrake.dev/schemas/scan-report.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "agentId",
    "scannerVersion",
    "generatedAt",
    "summary",
    "findings",
    "artifactHashes",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    agentId: { type: "string", minLength: 1 },
    scannerVersion: { type: "string", minLength: 1 },
    generatedAt: timestampSchema,
    summary: {
      type: "object",
      additionalProperties: false,
      required: ["critical", "high", "medium", "low", "info"],
      properties: {
        critical: { type: "integer", minimum: 0 },
        high: { type: "integer", minimum: 0 },
        medium: { type: "integer", minimum: 0 },
        low: { type: "integer", minimum: 0 },
        info: { type: "integer", minimum: 0 },
      },
    },
    findings: {
      type: "array",
      items: findingSchema,
    },
    artifactHashes: stringArraySchema,
  },
} as const;

export const toolCallEventSchema = {
  $id: "https://runbrake.dev/schemas/tool-call-event.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "agentId",
    "userId",
    "skill",
    "tool",
    "phase",
    "observedAt",
    "payloadClassifications",
    "destinationDomains",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    organizationId: { type: "string", minLength: 1 },
    agentId: { type: "string", minLength: 1 },
    userId: { type: "string", minLength: 1 },
    skill: { type: "string", minLength: 1 },
    tool: { type: "string", minLength: 1 },
    phase: { type: "string", enum: ["before", "after"] },
    observedAt: timestampSchema,
    environment: { type: "string", minLength: 1 },
    arguments: stringRecordSchema,
    payloadClassifications: stringArraySchema,
    destinationDomains: stringArraySchema,
  },
} as const;

export const installEventSchema = {
  $id: "https://runbrake.dev/schemas/install-event.json",
  type: "object",
  additionalProperties: false,
  required: ["id", "kind", "observedAt"],
  properties: {
    id: { type: "string", minLength: 1 },
    kind: { type: "string", enum: ["skill", "plugin"] },
    name: { type: "string", minLength: 1 },
    version: { type: "string", minLength: 1 },
    source: { type: "string", minLength: 1 },
    artifactPath: { type: "string", minLength: 1 },
    artifactHash: { type: "string", minLength: 32 },
    organizationId: { type: "string", minLength: 1 },
    agentId: { type: "string", minLength: 1 },
    userId: { type: "string", minLength: 1 },
    observedAt: timestampSchema,
    openclawFindings: stringArraySchema,
  },
} as const;

export const policyDecisionSchema = {
  $id: "https://runbrake.dev/schemas/policy-decision.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "eventId",
    "policyId",
    "action",
    "decidedAt",
    "reasons",
    "redactions",
    "failMode",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    eventId: { type: "string", minLength: 1 },
    policyId: { type: "string", minLength: 1 },
    action: {
      type: "string",
      enum: [
        "allow",
        "deny",
        "redact",
        "approve",
        "shadow",
        "quarantine",
        "kill_switch",
      ],
    },
    decidedAt: timestampSchema,
    reasons: stringArraySchema,
    redactions: stringArraySchema,
    failMode: { type: "string", enum: ["open", "closed"] },
  },
} as const;

export const approvalRequestSchema = {
  $id: "https://runbrake.dev/schemas/approval-request.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "eventId",
    "policyDecisionId",
    "organizationId",
    "status",
    "requestedAt",
    "expiresAt",
    "approvers",
    "evidenceHash",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    eventId: { type: "string", minLength: 1 },
    policyDecisionId: { type: "string", minLength: 1 },
    organizationId: { type: "string", minLength: 1 },
    status: {
      type: "string",
      enum: ["pending", "approved", "denied", "expired", "canceled"],
    },
    requestedAt: timestampSchema,
    expiresAt: timestampSchema,
    approvers: stringArraySchema,
    evidenceHash: { type: "string", minLength: 32 },
  },
} as const;

export const auditEventSchema = {
  $id: "https://runbrake.dev/schemas/audit-event.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "organizationId",
    "agentId",
    "eventType",
    "occurredAt",
    "actor",
    "subject",
    "evidenceHash",
    "previousHash",
    "signature",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    organizationId: { type: "string", minLength: 1 },
    agentId: { type: "string", minLength: 1 },
    eventType: { type: "string", minLength: 1 },
    occurredAt: timestampSchema,
    actor: { type: "string", minLength: 1 },
    subject: { type: "string", minLength: 1 },
    evidenceHash: { type: "string", minLength: 32 },
    previousHash: { type: ["string", "null"], minLength: 32 },
    signature: { type: "string", minLength: 32 },
  },
} as const;

export const contractSchemas = {
  Finding: findingSchema,
  ScanReport: scanReportSchema,
  ToolCallEvent: toolCallEventSchema,
  InstallEvent: installEventSchema,
  PolicyDecision: policyDecisionSchema,
  ApprovalRequest: approvalRequestSchema,
  AuditEvent: auditEventSchema,
} as const;

const findingSample: Finding = {
  id: "finding-gateway-public-bind",
  ruleId: "RB-GATEWAY-001",
  severity: "critical",
  confidence: 0.98,
  title: "Gateway is bound to a public interface",
  evidence: ["bind_host=0.0.0.0"],
  remediation: "Bind the gateway to localhost or a private network.",
};

export const validSamples = {
  Finding: findingSample,
  ScanReport: {
    id: "scan-2026-04-28-001",
    agentId: "agent-local-dev",
    scannerVersion: "0.0.0-dev",
    generatedAt: "2026-04-28T00:00:00Z",
    summary: {
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    findings: [findingSample],
    artifactHashes: [
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    ],
  } satisfies ScanReport,
  ToolCallEvent: {
    id: "event-001",
    organizationId: "org-local",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "google-workspace@1.4.2",
    tool: "gmail.send",
    phase: "before",
    observedAt: "2026-04-28T00:00:01Z",
    environment: "local",
    arguments: {
      recipient: "finance@vendor.example",
      authorization: "[REDACTED:oauth_token:11111111]",
    },
    payloadClassifications: ["customer_email", "attachment"],
    destinationDomains: ["vendor.example"],
  } satisfies ToolCallEvent,
  InstallEvent: {
    id: "install-001",
    kind: "plugin",
    name: "runbrake-policy",
    version: "0.1.0",
    source: "clawhub:runbrake-policy",
    artifactPath: "/tmp/openclaw-install/runbrake-policy",
    artifactHash:
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    organizationId: "org-local",
    agentId: "agent-local-dev",
    userId: "user-dev",
    observedAt: "2026-04-28T00:00:03Z",
    openclawFindings: ["built-in scan completed"],
  } satisfies InstallEvent,
  PolicyDecision: {
    id: "decision-001",
    eventId: "event-001",
    policyId: "policy-external-email-approval",
    action: "approve",
    decidedAt: "2026-04-28T00:00:02Z",
    reasons: ["recipient domain is outside the organization"],
    redactions: ["oauth_token"],
    failMode: "closed",
  } satisfies PolicyDecision,
  ApprovalRequest: {
    id: "approval-001",
    eventId: "event-001",
    policyDecisionId: "decision-001",
    organizationId: "org-001",
    status: "pending",
    requestedAt: "2026-04-28T00:00:03Z",
    expiresAt: "2026-04-28T00:10:03Z",
    approvers: ["owner"],
    evidenceHash:
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  } satisfies ApprovalRequest,
  AuditEvent: {
    id: "audit-001",
    organizationId: "org-001",
    agentId: "agent-local-dev",
    eventType: "policy.approval.requested",
    occurredAt: "2026-04-28T00:00:04Z",
    actor: "agent-local-dev",
    subject: "gmail.send",
    evidenceHash:
      "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    previousHash: null,
    signature:
      "ed25519:4444444444444444444444444444444444444444444444444444444444444444",
  } satisfies AuditEvent,
} as const;
