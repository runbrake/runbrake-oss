import type { AuditEvent, CheckReceipt, InstallEvent, PolicyDecision, RuntimeObservation, SessionNotice, ToolCallEvent } from "@runbrake/contracts";
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
    receipt?: CheckReceipt;
};
export type SidecarRuntimeObservationResponse = {
    observation?: RuntimeObservation;
    auditEvent?: AuditEvent;
    receipt?: CheckReceipt;
};
export type FetchLike = (url: string, init: {
    method: "GET" | "POST";
    headers: Record<string, string>;
    body: string;
}) => Promise<{
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
export type ReceiptVerbosity = "off" | "quiet" | "all";
export type SessionNoticeSink = (notice: SessionNotice) => unknown | Promise<unknown>;
export type ReceiptOptions = {
    receiptVerbosity?: ReceiptVerbosity;
    noticeSink?: SessionNoticeSink;
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
export type OpenClawBeforeToolCallHandler = (event: OpenClawBeforeToolCallEvent, context: OpenClawHookContext) => Promise<BeforeToolCallResult | undefined>;
export type BeforeInstallResult = {
    block?: boolean;
    blockReason?: string;
};
export type OpenClawBeforeInstallHandler = (event: OpenClawBeforeInstallEvent, context: OpenClawHookContext) => Promise<BeforeInstallResult | undefined>;
export type OpenClawPluginApi = {
    on(hookName: "before_tool_call", handler: OpenClawBeforeToolCallHandler, options?: {
        priority?: number;
    }): void;
    on(hookName: "before_install", handler: OpenClawBeforeInstallHandler, options?: {
        priority?: number;
    }): void;
};
export type BeforeToolCallHandlerOptions = SidecarClientOptions & ToolCallEventOptions & {
    organizationId?: string;
    agentId?: string;
    userId?: string;
    skill?: string;
    environment?: string;
    destinationDomains?: string[];
    payloadClassifications?: string[];
    priority?: number;
    recordRuntimeObservations?: boolean;
} & ReceiptOptions;
export type BeforeInstallHandlerOptions = SidecarClientOptions & InstallEventOptions & {
    priority?: number;
} & ReceiptOptions;
export declare function packageIdentity(): PackageIdentity;
export declare function toToolCallEvent(input: ToolCallInput, options?: ToolCallEventOptions): ToolCallEvent;
export declare function toInstallEvent(input: InstallInput, options?: InstallEventOptions): InstallEvent;
export declare function toRuntimeObservation(input: RuntimeObservationInput, options?: RuntimeObservationOptions): RuntimeObservation;
export declare function requestPolicyDecision(event: ToolCallEvent, options?: SidecarClientOptions): Promise<SidecarDecisionResponse>;
export declare function requestInstallDecision(event: InstallEvent, options?: SidecarClientOptions): Promise<SidecarDecisionResponse>;
export declare function requestRuntimeObservation(observation: RuntimeObservation, options?: SidecarClientOptions): Promise<SidecarRuntimeObservationResponse | undefined>;
export declare function createStartupReceipt(options?: SidecarClientOptions & ReceiptOptions): Promise<CheckReceipt>;
export declare function decisionToBeforeToolCallResult(decision: PolicyDecision): BeforeToolCallResult | undefined;
export declare function decisionToBeforeInstallResult(decision: PolicyDecision): BeforeInstallResult | undefined;
export declare function createBeforeToolCallHandler(options?: BeforeToolCallHandlerOptions): OpenClawBeforeToolCallHandler;
export declare function createBeforeInstallHandler(options?: BeforeInstallHandlerOptions): OpenClawBeforeInstallHandler;
export declare function registerRunBrakePluginHooks(api: OpenClawPluginApi, options?: BeforeToolCallHandlerOptions & BeforeInstallHandlerOptions): void;
export declare const runbrakeOpenClawPolicyPlugin: {
    id: string;
    name: string;
    description: string;
    register(api: OpenClawPluginApi): void;
};
export default runbrakeOpenClawPolicyPlugin;
//# sourceMappingURL=index.d.ts.map