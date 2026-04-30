import test from "node:test";
import assert from "node:assert/strict";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";

import { contractSchemas, validSamples } from "./index.js";

test("all Phase 0 contract schemas validate representative samples", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  type ContractName = keyof typeof contractSchemas;

  for (const name of Object.keys(contractSchemas) as ContractName[]) {
    const schema = contractSchemas[name] as AnySchema;
    const validate = ajv.compile(schema);
    const valid = validate(validSamples[name]);

    assert.equal(
      valid,
      true,
      `${name} sample failed validation: ${ajv.errorsText(validate.errors)}`,
    );
  }
});

test("finding schema rejects records without stable rule identifiers", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(contractSchemas.Finding);

  const valid = validate({
    id: "finding-1",
    severity: "high",
    confidence: 0.9,
    title: "Gateway exposed",
    evidence: ["bind_host=0.0.0.0"],
    remediation: "Bind to localhost.",
  });

  assert.equal(valid, false);
  assert.match(ajv.errorsText(validate.errors), /ruleId/);
});

test("tool call event schema allows redacted arguments and rejects raw payload fields", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(contractSchemas.ToolCallEvent);

  const valid = validate({
    id: "event-001",
    organizationId: "org-local",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "google-workspace@1.4.2",
    tool: "gmail.send",
    phase: "before",
    observedAt: "2026-04-28T00:00:01Z",
    environment: "prod",
    arguments: {
      recipient: "finance@vendor.example",
      authorization: "[REDACTED:oauth_token:11111111]",
    },
    payloadClassifications: ["customer_email"],
    destinationDomains: ["vendor.example"],
  });

  assert.equal(
    valid,
    true,
    `ToolCallEvent with redacted arguments failed validation: ${ajv.errorsText(validate.errors)}`,
  );

  const rejected = validate({
    id: "event-raw",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "google-workspace@1.4.2",
    tool: "gmail.send",
    phase: "before",
    observedAt: "2026-04-28T00:00:01Z",
    payloadClassifications: ["customer_email"],
    destinationDomains: ["vendor.example"],
    rawPayload: "Bearer ya29.supersecrettokenvalue",
  });

  assert.equal(rejected, false);
  assert.match(ajv.errorsText(validate.errors), /additional properties/);
});

test("install event schema allows metadata and rejects raw package payloads", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(contractSchemas.InstallEvent);

  const valid = validate({
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
  });

  assert.equal(
    valid,
    true,
    `InstallEvent metadata failed validation: ${ajv.errorsText(validate.errors)}`,
  );

  const rejected = validate({
    id: "install-raw",
    kind: "skill",
    observedAt: "2026-04-28T00:00:03Z",
    rawPackage: "sk-prod_1234567890abcdef",
  });

  assert.equal(rejected, false);
  assert.match(ajv.errorsText(validate.errors), /additional properties/);
});

test("runtime observation schema allows metadata and rejects raw payload fields", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(contractSchemas.RuntimeObservation);

  const valid = validate({
    id: "runtime-001",
    source: "openclaw.before_tool_call",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "gmail-helper",
    tool: "gmail.send",
    phase: "before",
    observedAt: "2026-04-29T00:00:01Z",
    destinationDomains: ["gmail.googleapis.com"],
    payloadClassifications: ["customer_email"],
    argumentKeys: ["authorization", "recipient"],
    argumentEvidence: {
      authorization: "[REDACTED:oauth_token:11111111]",
      recipient: "finance@example.com",
    },
  });

  assert.equal(
    valid,
    true,
    `RuntimeObservation metadata failed validation: ${ajv.errorsText(validate.errors)}`,
  );

  const rejected = validate({
    id: "runtime-raw",
    source: "openclaw.before_tool_call",
    agentId: "agent-local-dev",
    tool: "shell.exec",
    phase: "before",
    observedAt: "2026-04-29T00:00:01Z",
    destinationDomains: [],
    payloadClassifications: [],
    argumentKeys: ["token"],
    argumentEvidence: {},
    rawPayload: "Bearer ya29.supersecrettokenvalue",
  });

  assert.equal(rejected, false);
  assert.match(ajv.errorsText(validate.errors), /additional properties/);
});

test("check receipt schema allows safe local status metadata", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(contractSchemas.CheckReceipt);

  const valid = validate({
    id: "receipt-001",
    eventId: "event-shell",
    surface: "runtime",
    ecosystem: "openclaw",
    status: "blocked",
    severity: "critical",
    headline: "RunBrake blocked shell.exec",
    detail: "policy-shell-deny matched filesystem access",
    policyId: "policy-shell-deny",
    auditEventId: "audit-001",
    evidenceHash:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    ruleIds: ["RB-SKILL-SHELL-EXECUTION"],
    observedAt: "2026-04-29T18:00:00Z",
  });

  assert.equal(valid, true, ajv.errorsText(validate.errors));

  const rejected = validate({
    id: "receipt-raw",
    eventId: "event-shell",
    surface: "runtime",
    ecosystem: "hermes",
    status: "allowed",
    severity: "info",
    headline: "RunBrake checked terminal",
    detail: "allowed",
    ruleIds: [],
    observedAt: "2026-04-29T18:00:00Z",
    arguments: { token: "Bearer ya29.supersecrettokenvalue" },
  });

  assert.equal(rejected, false);
  assert.match(ajv.errorsText(validate.errors), /additional properties/);
});
