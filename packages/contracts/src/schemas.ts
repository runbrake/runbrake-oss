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

export type Dependency = {
  ecosystem: string;
  name: string;
  version?: string;
  manifestPath?: string;
  source?: string;
  direct?: boolean;
  dev?: boolean;
};

export type Vulnerability = {
  id: string;
  aliases?: string[];
  ecosystem: string;
  packageName: string;
  packageVersion?: string;
  severity?: string;
  severityType?: string;
  severityScore?: string;
  summary?: string;
  published?: string;
  modified?: string;
  fixedVersions?: string[];
  references?: string[];
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
  dependencies?: Dependency[];
  vulnerabilities?: Vulnerability[];
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

export type RuntimeObservation = {
  id: string;
  source: string;
  organizationId?: string;
  agentId: string;
  userId?: string;
  skill?: string;
  tool: string;
  phase: "before" | "after";
  observedAt: string;
  environment?: string;
  destinationDomains: string[];
  payloadClassifications: string[];
  argumentKeys: string[];
  argumentEvidence: Record<string, string>;
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

export type CheckReceipt = {
  id: string;
  eventId: string;
  surface: "startup" | "install" | "runtime" | "watch";
  ecosystem: "openclaw" | "hermes";
  status:
    | "active"
    | "allowed"
    | "shadowed"
    | "redacted"
    | "approval_required"
    | "blocked"
    | "quarantined"
    | "kill_switch"
    | "fail_open"
    | "observed";
  severity: Severity;
  headline: string;
  detail: string;
  policyId?: string;
  auditEventId?: string;
  evidenceHash?: string;
  ruleIds: string[];
  observedAt: string;
};

export type SessionNotice = {
  id: string;
  receiptId: string;
  channel: "agent_session" | "terminal" | "local_log";
  level: "info" | "warning" | "critical";
  message: string;
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
  $id: "https://runbrake.com/schemas/finding.json",
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
  $id: "https://runbrake.com/schemas/scan-report.json",
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
    dependencies: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["ecosystem", "name"],
        properties: {
          ecosystem: { type: "string", minLength: 1 },
          name: { type: "string", minLength: 1 },
          version: { type: "string", minLength: 1 },
          manifestPath: { type: "string", minLength: 1 },
          source: { type: "string", minLength: 1 },
          direct: { type: "boolean" },
          dev: { type: "boolean" },
        },
      },
    },
    vulnerabilities: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "ecosystem", "packageName"],
        properties: {
          id: { type: "string", minLength: 1 },
          aliases: stringArraySchema,
          ecosystem: { type: "string", minLength: 1 },
          packageName: { type: "string", minLength: 1 },
          packageVersion: { type: "string", minLength: 1 },
          severity: { type: "string", minLength: 1 },
          severityType: { type: "string", minLength: 1 },
          severityScore: { type: "string", minLength: 1 },
          summary: { type: "string", minLength: 1 },
          published: timestampSchema,
          modified: timestampSchema,
          fixedVersions: stringArraySchema,
          references: stringArraySchema,
        },
      },
    },
  },
} as const;

export const toolCallEventSchema = {
  $id: "https://runbrake.com/schemas/tool-call-event.json",
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
  $id: "https://runbrake.com/schemas/install-event.json",
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

export const runtimeObservationSchema = {
  $id: "https://runbrake.com/schemas/runtime-observation.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "source",
    "agentId",
    "tool",
    "phase",
    "observedAt",
    "destinationDomains",
    "payloadClassifications",
    "argumentKeys",
    "argumentEvidence",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    source: { type: "string", minLength: 1 },
    organizationId: { type: "string", minLength: 1 },
    agentId: { type: "string", minLength: 1 },
    userId: { type: "string", minLength: 1 },
    skill: { type: "string", minLength: 1 },
    tool: { type: "string", minLength: 1 },
    phase: { type: "string", enum: ["before", "after"] },
    observedAt: timestampSchema,
    environment: { type: "string", minLength: 1 },
    destinationDomains: stringArraySchema,
    payloadClassifications: stringArraySchema,
    argumentKeys: stringArraySchema,
    argumentEvidence: stringRecordSchema,
  },
} as const;

export const policyDecisionSchema = {
  $id: "https://runbrake.com/schemas/policy-decision.json",
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
  $id: "https://runbrake.com/schemas/approval-request.json",
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
  $id: "https://runbrake.com/schemas/audit-event.json",
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

export const checkReceiptSchema = {
  $id: "https://runbrake.com/schemas/check-receipt.json",
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "eventId",
    "surface",
    "ecosystem",
    "status",
    "severity",
    "headline",
    "detail",
    "ruleIds",
    "observedAt",
  ],
  properties: {
    id: { type: "string", minLength: 1 },
    eventId: { type: "string", minLength: 1 },
    surface: {
      type: "string",
      enum: ["startup", "install", "runtime", "watch"],
    },
    ecosystem: { type: "string", enum: ["openclaw", "hermes"] },
    status: {
      type: "string",
      enum: [
        "active",
        "allowed",
        "shadowed",
        "redacted",
        "approval_required",
        "blocked",
        "quarantined",
        "kill_switch",
        "fail_open",
        "observed",
      ],
    },
    severity: {
      type: "string",
      enum: ["critical", "high", "medium", "low", "info"],
    },
    headline: { type: "string", minLength: 1 },
    detail: { type: "string", minLength: 1 },
    policyId: { type: "string", minLength: 1 },
    auditEventId: { type: "string", minLength: 1 },
    evidenceHash: { type: "string", minLength: 32 },
    ruleIds: {
      type: "array",
      items: { type: "string", minLength: 1 },
    },
    observedAt: timestampSchema,
  },
} as const;

export const sessionNoticeSchema = {
  $id: "https://runbrake.com/schemas/session-notice.json",
  type: "object",
  additionalProperties: false,
  required: ["id", "receiptId", "channel", "level", "message"],
  properties: {
    id: { type: "string", minLength: 1 },
    receiptId: { type: "string", minLength: 1 },
    channel: {
      type: "string",
      enum: ["agent_session", "terminal", "local_log"],
    },
    level: { type: "string", enum: ["info", "warning", "critical"] },
    message: { type: "string", minLength: 1 },
  },
} as const;

export const contractSchemas = {
  Finding: findingSchema,
  ScanReport: scanReportSchema,
  ToolCallEvent: toolCallEventSchema,
  InstallEvent: installEventSchema,
  RuntimeObservation: runtimeObservationSchema,
  PolicyDecision: policyDecisionSchema,
  ApprovalRequest: approvalRequestSchema,
  AuditEvent: auditEventSchema,
  CheckReceipt: checkReceiptSchema,
  SessionNotice: sessionNoticeSchema,
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
  RuntimeObservation: {
    id: "runtime-001",
    source: "openclaw.before_tool_call",
    organizationId: "org-local",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "google-workspace@1.4.2",
    tool: "gmail.send",
    phase: "before",
    observedAt: "2026-04-28T00:00:03Z",
    environment: "local",
    destinationDomains: ["gmail.googleapis.com"],
    payloadClassifications: ["customer_email"],
    argumentKeys: ["authorization", "recipient"],
    argumentEvidence: {
      authorization: "[REDACTED:oauth_token:11111111]",
      recipient: "finance@vendor.example",
    },
  } satisfies RuntimeObservation,
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
  CheckReceipt: {
    id: "receipt-001",
    eventId: "event-001",
    surface: "runtime",
    ecosystem: "openclaw",
    status: "approval_required",
    severity: "medium",
    headline: "RunBrake checked gmail.send",
    detail: "policy-external-email-approval requires approval",
    policyId: "policy-external-email-approval",
    auditEventId: "audit-001",
    evidenceHash:
      "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    ruleIds: ["RB-SKILL-UNKNOWN-EGRESS"],
    observedAt: "2026-04-28T00:00:04Z",
  } satisfies CheckReceipt,
  SessionNotice: {
    id: "notice-001",
    receiptId: "receipt-001",
    channel: "agent_session",
    level: "warning",
    message:
      "RunBrake checked gmail.send - approval_required - policy-external-email-approval",
  } satisfies SessionNotice,
} as const;
