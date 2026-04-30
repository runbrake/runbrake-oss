import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_SIDECAR_URL = "http://127.0.0.1:47838"
DEFAULT_TIMEOUT_SECONDS = 1.5
DEFAULT_ARGUMENT_LENGTH = 256
BLOCKING_ACTIONS = {"deny", "quarantine", "kill_switch"}
PASS_THROUGH_ACTIONS = {"allow", "shadow", "redact", "approve"}
QUIET_RECEIPT_STATUSES = {
    "shadowed",
    "redacted",
    "approval_required",
    "blocked",
    "quarantined",
    "kill_switch",
    "fail_open",
}

SECRET_PATTERNS = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
    ),
    ("api_key", re.compile(r"sk-[A-Za-z0-9_-]{16,}")),
    ("aws_access_key", re.compile(r"\bA(KIA|SIA)[A-Z0-9]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_(live|test)_[A-Za-z0-9]{16,}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9_]{16,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{32,}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b"),
    ),
    ("oauth_token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("oauth_token", re.compile(r"ya29\.[A-Za-z0-9._-]{16,}")),
    (
        "session_cookie",
        re.compile(r"(session|cookie)[_-]?(token|secret)?[\"'=:\s]+[A-Za-z0-9._~+/=-]{20,}", re.I),
    ),
    ("database_url", re.compile(r"(postgres|mysql|mongodb)://[^\s\"']+", re.I)),
]

URL_PATTERN = re.compile(r"\b(?:https?|wss?|postgres|mysql|mongodb)://[^\s\"'<>]+", re.I)
CREDENTIAL_KEY_PATTERN = re.compile(
    r"(authorization|api[_-]?key|token|secret|password|cookie|credential|private[_-]?key)",
    re.I,
)


def build_runtime_observation(tool_name: str, args: dict, task_id: str) -> dict:
    safe_args = _dict_args(args)
    argument_evidence = redact_argument_evidence(safe_args)
    argument_keys = sorted(str(key) for key in safe_args.keys())
    domains = extract_domains(safe_args)
    classifications = classify_payload(safe_args, domains, argument_evidence)
    observed_at = utc_now()
    event_id = stable_event_id(
        tool_name,
        argument_keys,
        argument_evidence,
        task_id,
        observed_at,
        str(uuid.uuid4()),
    )

    return {
        "id": event_id,
        "source": "hermes.pre_tool_call",
        "agentId": "hermes",
        "tool": str(tool_name),
        "phase": "before",
        "observedAt": observed_at,
        "destinationDomains": domains,
        "payloadClassifications": classifications,
        "argumentKeys": argument_keys,
        "argumentEvidence": argument_evidence,
    }


def pre_tool_call(tool_name, args, task_id, **kwargs):
    observation = build_runtime_observation(tool_name, args, task_id)
    sidecar_url = _sidecar_url(kwargs.get("sidecar_url"))
    timeout = kwargs.get("timeout", DEFAULT_TIMEOUT_SECONDS)
    verbosity = _receipt_verbosity(kwargs.get("receipt_verbosity"))

    observation_response = _post_json(f"{sidecar_url}/v1/runtime/observation", observation, timeout)
    if observation_response is None:
        _emit_receipt(
            _fail_open_receipt(
                observation["id"],
                "runtime",
                observation["tool"],
                observation["observedAt"],
                "runtime observation endpoint unavailable",
            ),
            verbosity,
        )
        return None
    _emit_receipt(_receipt_from_response(observation_response), verbosity)

    event = _build_tool_call_event(observation, kwargs)
    response = _post_json(f"{sidecar_url}/v1/policy/decision", event, timeout)
    decision = _decision_from_response(response)
    if not decision:
        _emit_receipt(
            _fail_open_receipt(
                observation["id"],
                "runtime",
                observation["tool"],
                observation["observedAt"],
                "policy decision endpoint unavailable",
            ),
            verbosity,
        )
        return None
    _emit_receipt(_receipt_from_response(response), verbosity)

    action = str(decision.get("action", "")).strip()
    if action in PASS_THROUGH_ACTIONS:
        return None
    if action not in BLOCKING_ACTIONS:
        return None

    policy_id = str(decision.get("policyId") or "unknown-policy")
    reason = _first_reason(decision)
    return {
        "action": "block",
        "message": f"RunBrake blocked {policy_id}: {reason}",
    }


def register(ctx):
    ctx.register_hook("pre_tool_call", pre_tool_call)


def startup_receipt(sidecar_url=None, timeout=DEFAULT_TIMEOUT_SECONDS, receipt_verbosity=None):
    observed_at = utc_now()
    verbosity = _receipt_verbosity(receipt_verbosity)
    response = _get_json(f"{_sidecar_url(sidecar_url)}/healthz", timeout)
    if response is None:
        receipt = {
            "id": stable_event_id("startup", [], {}, "fail_open", observed_at, "runbrake"),
            "eventId": f"startup-{observed_at}",
            "surface": "startup",
            "ecosystem": "hermes",
            "status": "fail_open",
            "severity": "high",
            "headline": "RunBrake not enforcing",
            "detail": "sidecar unavailable - agent will fail open locally",
            "policyId": "policy-sidecar-unavailable",
            "ruleIds": [],
            "observedAt": observed_at,
        }
    else:
        receipt = {
            "id": stable_event_id("startup", [], {}, "active", observed_at, "runbrake"),
            "eventId": f"startup-{observed_at}",
            "surface": "startup",
            "ecosystem": "hermes",
            "status": "active",
            "severity": "info",
            "headline": "RunBrake active",
            "detail": "sidecar connected - policy checks visible in this session",
            "ruleIds": [],
            "observedAt": observed_at,
        }
    _emit_receipt(receipt, verbosity)
    return receipt


def extract_domains(args: dict) -> list[str]:
    domains = set()
    for value in _walk_values(args):
        text = stringify_value(value)
        for candidate in _extract_domains_from_text(text):
            domains.add(candidate)
    return sorted(domains)


def classify_payload(args: dict, domains=None, argument_evidence=None) -> list[str]:
    labels = set()
    if domains:
        labels.add("network")

    evidence = argument_evidence if argument_evidence is not None else redact_argument_evidence(args)
    for key, value in evidence.items():
        if CREDENTIAL_KEY_PATTERN.search(str(key)) or "[REDACTED:" in value:
            labels.add("credential")
        if re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", value, re.I):
            labels.add("email")

    return sorted(labels)


def redact_argument_evidence(args: dict) -> dict[str, str]:
    evidence = {}
    for key in sorted(args.keys(), key=lambda item: str(item)):
        evidence[str(key)] = truncate(stringify_value(redact_sensitive_value(str(key), args[key])))
    return evidence


def stable_event_id(tool_name, argument_keys, argument_evidence, task_id, observed_at=None, nonce=None) -> str:
    payload = {
        "tool": str(tool_name),
        "taskId": "" if task_id is None else str(task_id),
        "observedAt": "" if observed_at is None else str(observed_at),
        "nonce": "" if nonce is None else str(nonce),
        "argumentKeys": list(argument_keys),
        "argumentEvidence": argument_evidence,
    }
    return "event-" + _hash(json.dumps(payload, sort_keys=True, separators=(",", ":")))[:16]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stringify_value(value) -> str:
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def redact_secret_value(value: str) -> str:
    redacted = value
    for kind, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: _redaction_marker(kind, match.group(0)), redacted)
    return redacted


def redact_sensitive_value(key: str, value):
    if CREDENTIAL_KEY_PATTERN.search(str(key)):
        text = stringify_value(value)
        redacted = redact_secret_value(text)
        if redacted != text:
            return redacted
        return _redaction_marker("credential", text)
    if isinstance(value, dict):
        return {
            str(child_key): redact_sensitive_value(str(child_key), child_value)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_value("", item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive_value("", item) for item in value]
    if isinstance(value, set):
        return [redact_sensitive_value("", item) for item in sorted(value, key=lambda item: stringify_value(item))]
    return redact_secret_value(stringify_value(value))


def truncate(value: str, max_length: int = DEFAULT_ARGUMENT_LENGTH) -> str:
    if len(value) <= max_length:
        return value
    return value[: max(0, max_length - 15)] + "[TRUNCATED]"


def _build_tool_call_event(observation: dict, kwargs: dict) -> dict:
    event = {
        "id": observation["id"],
        "agentId": kwargs.get("agent_id") or kwargs.get("agentId") or "hermes",
        "userId": kwargs.get("user_id") or kwargs.get("userId") or "hermes-local",
        "skill": kwargs.get("skill") or kwargs.get("skill_name") or "hermes-runtime",
        "tool": observation["tool"],
        "phase": "before",
        "observedAt": observation["observedAt"],
        "arguments": dict(observation["argumentEvidence"]),
        "payloadClassifications": list(observation["payloadClassifications"]),
        "destinationDomains": list(observation["destinationDomains"]),
    }
    _assign_if_present(event, "organizationId", kwargs.get("organization_id") or kwargs.get("organizationId"))
    _assign_if_present(event, "environment", kwargs.get("environment") or "local")
    return event


def _post_json(url: str, payload: dict, timeout: float):
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"content-type": "application/json", "accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            response_body = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return None

    try:
        return json.loads(response_body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _get_json(url: str, timeout: float):
    request = Request(
        url,
        headers={"accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            response_body = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return None

    try:
        return json.loads(response_body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _decision_from_response(response):
    if not isinstance(response, dict):
        return None
    decision = response.get("decision", response)
    if not isinstance(decision, dict):
        return None
    return decision


def _receipt_from_response(response):
    if not isinstance(response, dict):
        return None
    receipt = response.get("receipt")
    if not isinstance(receipt, dict):
        return None
    return receipt


def _receipt_verbosity(explicit=None) -> str:
    value = explicit or os.environ.get("RUNBRAKE_RECEIPTS") or "quiet"
    normalized = str(value).strip().lower()
    if normalized in {"off", "quiet", "all"}:
        return normalized
    return "quiet"


def _emit_receipt(receipt, verbosity: str):
    if not _should_emit_receipt(receipt, verbosity):
        return
    print(_receipt_message(receipt), file=sys.stderr)


def _should_emit_receipt(receipt, verbosity: str) -> bool:
    if not isinstance(receipt, dict) or verbosity == "off":
        return False
    if verbosity == "all":
        return True
    if receipt.get("surface") == "startup":
        return True
    return str(receipt.get("status", "")).strip() in QUIET_RECEIPT_STATUSES


def _receipt_message(receipt: dict) -> str:
    headline = str(receipt.get("headline") or "RunBrake checked action")
    status = str(receipt.get("status") or "observed")
    policy_id = str(receipt.get("policyId") or "").strip()
    if policy_id:
        return f"{headline} - {status} - {policy_id}"
    return f"{headline} - {status}"


def _fail_open_receipt(event_id: str, surface: str, subject: str, observed_at: str, detail: str) -> dict:
    return {
        "id": stable_event_id("receipt", [event_id, surface], {"status": "fail_open"}, "hermes", observed_at),
        "eventId": event_id,
        "surface": surface,
        "ecosystem": "hermes",
        "status": "fail_open",
        "severity": "high",
        "headline": f"RunBrake not enforcing {subject}",
        "detail": detail,
        "policyId": "policy-sidecar-unavailable",
        "ruleIds": [],
        "observedAt": observed_at,
    }


def _first_reason(decision: dict) -> str:
    reasons = decision.get("reasons")
    if isinstance(reasons, list):
        for reason in reasons:
            if str(reason).strip():
                return str(reason)
    return "policy decision blocked this tool call"


def _sidecar_url(explicit_url=None) -> str:
    url = explicit_url or os.environ.get("RUNBRAKE_SIDECAR_URL") or DEFAULT_SIDECAR_URL
    return str(url).rstrip("/")


def _dict_args(args) -> dict:
    if isinstance(args, dict):
        return args
    return {}


def _walk_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_values(item)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_values(item)
        return
    yield value


def _extract_domains_from_text(text: str):
    for match in URL_PATTERN.finditer(text):
        parsed = urlparse(match.group(0))
        if parsed.hostname:
            yield parsed.hostname.lower()


def _assign_if_present(target: dict, key: str, value):
    if value not in (None, ""):
        target[key] = value


def _redaction_marker(kind: str, raw: str) -> str:
    return f"[REDACTED:{kind}:{_hash(raw)[:8]}]"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
