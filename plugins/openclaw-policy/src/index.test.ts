import test from "node:test";
import assert from "node:assert/strict";

import {
  createBeforeInstallHandler,
  createBeforeToolCallHandler,
  decisionToBeforeInstallResult,
  decisionToBeforeToolCallResult,
  packageIdentity,
  requestInstallDecision,
  requestPolicyDecision,
  toInstallEvent,
  toToolCallEvent,
  type FetchLike,
  type OpenClawPluginApi,
} from "./index.js";

test("OpenClaw policy plugin package exposes phase 3 identity", () => {
  assert.deepEqual(packageIdentity(), {
    name: "@runbrake/openclaw-policy",
    phase: "sidecar-shadow-policy",
  });
});

test("toToolCallEvent creates a metadata-first event with redacted arguments", () => {
  const event = toToolCallEvent(
    {
      organizationId: "org-local",
      agentId: "agent-local-dev",
      userId: "user-dev",
      skill: "google-workspace@1.4.2",
      tool: "gmail.send",
      environment: "prod",
      destinationDomains: ["vendor.example"],
      payloadClassifications: ["customer_email"],
      arguments: {
        recipient: "finance@vendor.example",
        authorization: "Bearer ya29.supersecrettokenvalue",
        nested: { body: "hello" },
      },
    },
    { now: new Date("2026-04-28T00:00:01Z"), maxArgumentLength: 80 },
  );

  assert.equal(event.organizationId, "org-local");
  assert.equal(event.phase, "before");
  assert.equal(event.environment, "prod");
  assert.deepEqual(event.destinationDomains, ["vendor.example"]);
  assert.equal(event.arguments?.recipient, "finance@vendor.example");
  assert.match(event.arguments?.authorization ?? "", /\[REDACTED:oauth_token:/);
  assert.doesNotMatch(
    JSON.stringify(event),
    /ya29\.supersecrettokenvalue|Bearer ya29/,
  );
  assert.equal(event.arguments?.nested, '{"body":"hello"}');
});

test("requestPolicyDecision returns sidecar decision responses", async () => {
  const event = toToolCallEvent({
    id: "event-001",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "shell@1.0.0",
    tool: "shell.exec",
    payloadClassifications: ["filesystem"],
    destinationDomains: [],
  });
  let postedBody = "";
  const fetchImpl: FetchLike = async (_url, init) => {
    postedBody = init.body;
    return {
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        decision: {
          id: "decision-001",
          eventId: event.id,
          policyId: "policy-shell-deny",
          action: "shadow",
          decidedAt: "2026-04-28T00:00:02Z",
          reasons: ["shadow mode: would have denied shell execution"],
          redactions: [],
          failMode: "open",
        },
      }),
    };
  };

  const response = await requestPolicyDecision(event, {
    sidecarUrl: "http://127.0.0.1:47838",
    fetchImpl,
  });

  assert.equal(response.decision.policyId, "policy-shell-deny");
  assert.equal(response.decision.action, "shadow");
  assert.match(postedBody, /"tool":"shell.exec"/);
});

test("requestPolicyDecision fails open when sidecar is unavailable", async () => {
  const event = toToolCallEvent({
    id: "event-offline",
    agentId: "agent-local-dev",
    userId: "user-dev",
    skill: "shell@1.0.0",
    tool: "shell.exec",
    payloadClassifications: ["filesystem"],
    destinationDomains: [],
  });
  const fetchImpl: FetchLike = async () => {
    throw new Error("connection refused");
  };

  const response = await requestPolicyDecision(event, {
    fetchImpl,
    now: new Date("2026-04-28T00:00:03Z"),
  });

  assert.equal(response.decision.eventId, "event-offline");
  assert.equal(response.decision.policyId, "policy-sidecar-unavailable");
  assert.equal(response.decision.action, "shadow");
  assert.equal(response.decision.failMode, "open");
  assert.match(response.decision.reasons.join(" "), /connection refused/);
});

test("toInstallEvent creates a metadata-only install event", () => {
  const event = toInstallEvent(
    {
      id: "install-001",
      kind: "plugin",
      name: "shell-helper",
      version: "1.0.0",
      source: "clawhub:shell-helper",
      artifactPath: "/tmp/openclaw-install/shell-helper",
      artifactHash:
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      openclawFindings: ["built-in scan completed"],
      rawPackage: "sk-prod_1234567890abcdef",
    },
    {
      organizationId: "org-local",
      agentId: "agent-local-dev",
      userId: "user-dev",
      now: new Date("2026-04-28T00:00:07Z"),
    },
  );

  assert.equal(event.id, "install-001");
  assert.equal(event.kind, "plugin");
  assert.equal(event.name, "shell-helper");
  assert.equal(event.agentId, "agent-local-dev");
  assert.deepEqual(event.openclawFindings, ["built-in scan completed"]);
  assert.doesNotMatch(JSON.stringify(event), /sk-prod_1234567890abcdef/);
});

test("requestInstallDecision posts to the install decision endpoint", async () => {
  const event = toInstallEvent({
    id: "install-002",
    kind: "skill",
    name: "email-tool",
  });
  let postedURL = "";
  let postedBody = "";
  const fetchImpl: FetchLike = async (url, init) => {
    postedURL = url;
    postedBody = init.body;
    return {
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        decision: {
          id: "decision-install",
          eventId: event.id,
          policyId: "policy-install-critical-finding",
          action: "deny",
          decidedAt: "2026-04-28T00:00:08Z",
          reasons: ["critical install finding"],
          redactions: [],
          failMode: "closed",
        },
      }),
    };
  };

  const response = await requestInstallDecision(event, { fetchImpl });

  assert.match(postedURL, /\/v1\/install\/decision$/);
  assert.match(postedBody, /"kind":"skill"/);
  assert.equal(response.decision.action, "deny");
});

test("decisionToBeforeInstallResult blocks enforced terminal install decisions", () => {
  const result = decisionToBeforeInstallResult({
    id: "decision-install-deny",
    eventId: "install-shell",
    policyId: "policy-install-critical-finding",
    action: "deny",
    decidedAt: "2026-04-28T00:00:09Z",
    reasons: ["plugin install matched critical rule"],
    redactions: [],
    failMode: "closed",
  });

  assert.deepEqual(result, {
    block: true,
    blockReason:
      "RunBrake blocked install policy-install-critical-finding: plugin install matched critical rule",
  });
});

test("createBeforeInstallHandler maps OpenClaw install events to sidecar blocking results", async () => {
  const fetchImpl: FetchLike = async (_url, init) => {
    assert.match(init.body, /"kind":"plugin"/);
    assert.match(
      init.body,
      /"artifactPath":"\/tmp\/openclaw-install\/shell-helper"/,
    );
    assert.doesNotMatch(init.body, /sk-prod_1234567890abcdef/);

    return {
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        decision: {
          id: "decision-install-deny",
          eventId: "install-tool-call",
          policyId: "policy-install-critical-finding",
          action: "deny",
          decidedAt: "2026-04-28T00:00:10Z",
          reasons: ["plugin install matched critical rule"],
          redactions: [],
          failMode: "closed",
        },
      }),
    };
  };
  const handler = createBeforeInstallHandler({
    fetchImpl,
    organizationId: "org-local",
    userId: "user-dev",
    now: new Date("2026-04-28T00:00:10Z"),
  });

  const result = await handler(
    {
      installId: "install-tool-call",
      kind: "plugin",
      name: "shell-helper",
      source: "clawhub:shell-helper",
      artifactPath: "/tmp/openclaw-install/shell-helper",
      rawPackage: "sk-prod_1234567890abcdef",
    },
    { agentId: "agent-local-dev", sessionId: "session-001" },
  );

  assert.deepEqual(result, {
    block: true,
    blockReason:
      "RunBrake blocked install policy-install-critical-finding: plugin install matched critical rule",
  });
});

test("createBeforeInstallHandler maps real OpenClaw before_install payloads", async () => {
  const fetchImpl: FetchLike = async (_url, init) => {
    assert.match(init.body, /"kind":"plugin"/);
    assert.match(init.body, /"name":"bad-openclaw-plugin"/);
    assert.match(init.body, /"source":"\/tmp\/incoming\/bad-plugin"/);
    assert.match(init.body, /"artifactPath":"\/tmp\/incoming\/bad-plugin"/);
    assert.match(init.body, /"openclawFindings":/);
    assert.match(init.body, /critical: dangerous code pattern/);
    assert.doesNotMatch(init.body, /sk-prod_1234567890abcdef/);

    return {
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        decision: {
          id: "decision-install-deny",
          eventId: "install-tool-call",
          policyId: "policy-install-critical-finding",
          action: "deny",
          decidedAt: "2026-04-28T00:00:11Z",
          reasons: ["plugin install matched critical rule"],
          redactions: [],
          failMode: "closed",
        },
      }),
    };
  };
  const handler = createBeforeInstallHandler({
    fetchImpl,
    userId: "user-dev",
    now: new Date("2026-04-28T00:00:11Z"),
  });

  const result = await handler(
    {
      targetType: "plugin",
      targetName: "bad-openclaw-plugin",
      sourcePath: "/tmp/incoming/bad-plugin",
      sourcePathKind: "directory",
      request: {
        kind: "plugin-dir",
        mode: "install",
        requestedSpecifier: "/tmp/incoming/bad-plugin",
      },
      builtinScan: {
        status: "ok",
        scannedFiles: 3,
        critical: 1,
        warn: 0,
        info: 0,
        findings: [
          {
            severity: "critical",
            message: "dangerous code pattern",
            file: "SKILL.md",
            line: 4,
          },
        ],
      },
      plugin: {
        contentType: "package",
        pluginId: "bad-openclaw-plugin",
        packageName: "bad-openclaw-plugin",
        manifestId: "bad-openclaw-plugin",
        version: "0.0.0",
        extensions: ["./index.js"],
      },
      rawPackage: "sk-prod_1234567890abcdef",
    },
    { agentId: "agent-local-dev", sessionId: "session-001" },
  );

  assert.deepEqual(result, {
    block: true,
    blockReason:
      "RunBrake blocked install policy-install-critical-finding: plugin install matched critical rule",
  });
});

test("decisionToBeforeToolCallResult blocks enforced terminal decisions", () => {
  const result = decisionToBeforeToolCallResult({
    id: "decision-deny",
    eventId: "event-shell",
    policyId: "policy-shell-deny",
    action: "deny",
    decidedAt: "2026-04-28T00:00:04Z",
    reasons: ["shell execution is blocked by policy"],
    redactions: [],
    failMode: "closed",
  });

  assert.deepEqual(result, {
    block: true,
    blockReason:
      "RunBrake blocked policy-shell-deny: shell execution is blocked by policy",
  });
});

test("decisionToBeforeToolCallResult treats shadow and fail-open decisions as no hook decision", () => {
  assert.equal(
    decisionToBeforeToolCallResult({
      id: "decision-shadow",
      eventId: "event-shell",
      policyId: "policy-shell-shadow",
      action: "shadow",
      decidedAt: "2026-04-28T00:00:05Z",
      reasons: ["shadow mode: would have returned deny"],
      redactions: [],
      failMode: "open",
    }),
    undefined,
  );
});

test("createBeforeToolCallHandler maps OpenClaw tool events to sidecar blocking results", async () => {
  const fetchImpl: FetchLike = async (_url, init) => {
    assert.match(init.body, /"tool":"shell.exec"/);
    assert.match(init.body, /"command":"rm -rf \/tmp\/example"/);
    assert.doesNotMatch(init.body, /ya29\.supersecrettokenvalue/);

    return {
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({
        decision: {
          id: "decision-deny",
          eventId: "event-tool-call",
          policyId: "policy-shell-deny",
          action: "deny",
          decidedAt: "2026-04-28T00:00:06Z",
          reasons: ["shell execution is blocked by policy"],
          redactions: ["arguments.authorization"],
          failMode: "closed",
        },
      }),
    };
  };
  const handler = createBeforeToolCallHandler({
    fetchImpl,
    organizationId: "org-local",
    environment: "prod",
    userId: "user-dev",
    skill: "openclaw-runtime",
    now: new Date("2026-04-28T00:00:06Z"),
  });

  const result = await handler(
    {
      toolName: "shell.exec",
      toolCallId: "event-tool-call",
      params: {
        command: "rm -rf /tmp/example",
        authorization: "Bearer ya29.supersecrettokenvalue",
      },
    },
    { agentId: "agent-local-dev", sessionId: "session-001" },
  );

  assert.deepEqual(result, {
    block: true,
    blockReason:
      "RunBrake blocked policy-shell-deny: shell execution is blocked by policy",
  });
});

test("default plugin entry registers install and tool-call hooks", async () => {
  const registered: Array<{
    hookName: string;
    handler: unknown;
    options: unknown;
  }> = [];
  const api: OpenClawPluginApi = {
    on(hookName, handler, options) {
      registered.push({ hookName, handler, options });
    },
  };

  const entry = (await import("./index.js")).default;
  entry.register(api);

  assert.equal(entry.id, "runbrake-policy");
  assert.equal(registered.length, 2);
  assert.deepEqual(registered.map((entry) => entry.hookName).sort(), [
    "before_install",
    "before_tool_call",
  ]);
  assert.deepEqual(registered[0]?.options, { priority: 100 });
  assert.deepEqual(registered[1]?.options, { priority: 100 });
});
