from flask import Flask, request, jsonify
from urllib.parse import unquote, urlparse
from html import unescape
from datetime import datetime, timezone
import re

app = Flask(__name__)


# ============================================================
# Q1 — RELEASE GATE
# ============================================================

EXPECTED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

SHA40 = re.compile(r"^[0-9a-f]{40}$")


@app.post("/release-gate")
def release_gate():
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({
            "decision": "block",
            "violations": ["EXCESS_PERMISSION"]
        })

    workflow = body.get("workflow")
    image = body.get("image")

    if not isinstance(workflow, dict):
        workflow = {}

    if not isinstance(image, dict):
        image = {}

    violations = []

    # Exact permissions
    if workflow.get("permissions") != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # Pull request trigger
    if body.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # Tests / matrix / failFast
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # Actions
    actions = workflow.get("actions", [])
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                violations.append("MUTABLE_ACTION")
                continue

            owner = action.get("owner")
            ref = action.get("ref")

            if owner == "actions":
                # Version tags are permitted for actions-owned actions.
                continue

            if not isinstance(ref, str) or not SHA40.fullmatch(ref):
                violations.append("MUTABLE_ACTION")

    # Image
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Production
    if body.get("target") == "production":
        if (
            body.get("event") != "push"
            or body.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return jsonify({
        "decision": "promote" if not violations else "block",
        "violations": violations
    })


# ============================================================
# Q2 — ACTION FIREWALL
# ============================================================

TENANT = "tenant-36k4fs9"
EMAIL_DOMAIN = "notify-rmnhsv9.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def action_result(decision, reason):
    return jsonify({
        "decision": decision,
        "reason": reason
    })


@app.post("/action-firewall")
def action_firewall():
    body = request.get_json(silent=True)

    # 1. Top-level schema
    if not isinstance(body, dict):
        return action_result("block", "INVALID_SCHEMA")

    if body.get("provenance") not in {"trusted", "untrusted"}:
        return action_result("block", "INVALID_SCHEMA")

    if not isinstance(body.get("humanApproved"), bool):
        return action_result("block", "INVALID_SCHEMA")

    if "untrustedContent" in body and not isinstance(
        body["untrustedContent"], str
    ):
        return action_result("block", "INVALID_SCHEMA")

    action = body.get("action")

    if not isinstance(action, dict):
        return action_result("block", "INVALID_SCHEMA")

    if "tool" not in action or "args" not in action:
        return action_result("block", "INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return action_result("block", "INVALID_SCHEMA")

    if not isinstance(action["args"], dict):
        return action_result("block", "INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]

    # 2. Tool allowlist
    if tool not in ALLOWED_TOOLS:
        return action_result("block", "TOOL_NOT_ALLOWED")

    # 3. Tool argument schema
    if tool == "search":
        if (
            set(args.keys()) != {"query"}
            or not isinstance(args["query"], str)
            or not 1 <= len(args["query"]) <= 200
        ):
            return action_result("block", "INVALID_SCHEMA")

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return action_result("block", "INVALID_SCHEMA")

        if (
            not isinstance(args["tenantId"], str)
            or not isinstance(args["recordId"], str)
            or args["recordId"] == ""
        ):
            return action_result("block", "INVALID_SCHEMA")

        # Tenant scope
        if args["tenantId"] != TENANT:
            return action_result("block", "TENANT_SCOPE")

    elif tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return action_result("block", "INVALID_SCHEMA")

        if not all(
            isinstance(args[k], str)
            for k in ("to", "subject", "body")
        ):
            return action_result("block", "INVALID_SCHEMA")

        # Exact recipient domain.
        if "@" not in args["to"]:
            return action_result("block", "EGRESS_DENIED")

        domain = args["to"].rsplit("@", 1)[1]

        if domain != EMAIL_DOMAIN:
            return action_result("block", "EGRESS_DENIED")

        if body["humanApproved"] is not True:
            return action_result("block", "APPROVAL_REQUIRED")

    elif tool == "render_html":
        if set(args.keys()) != {"html"}:
            return action_result("block", "INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return action_result("block", "INVALID_SCHEMA")

        html = args["html"]

        if re.search(
            r"<\s*(script|iframe|object|embed)\b",
            html,
            re.I
        ):
            return action_result("block", "UNSAFE_OUTPUT")

        if re.search(
            r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
            html,
            re.I
        ):
            return action_result("block", "UNSAFE_OUTPUT")

        if re.search(
            r"javascript\s*:|vbscript\s*:|data\s*:",
            html,
            re.I
        ):
            return action_result("block", "UNSAFE_OUTPUT")

    return action_result("allow", "ALLOW")


# ============================================================
# Q3 — TERRAFORM PLAN
# ============================================================

TF_ENVIRONMENT = "prod-4tx5cu"

REQUIRED_LABELS = {
    "owner": "student-b2diq",
    "environment": "production",
    "cost_center": "cc-0zts",
}

VALID_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

DESTRUCTIVE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


@app.post("/terraform/plan")
def terraform_plan():
    body = request.get_json(silent=True)

    # 1. Request/nested object types
    if not isinstance(body, dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(body.get("environment"), str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(body.get("state"), dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(body.get("providerVersion"), str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(body.get("destroyApproved"), bool):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(body.get("resource"), dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    state = body["state"]

    if not isinstance(state.get("backend"), str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(state.get("locked"), bool):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    resource = body["resource"]

    if not isinstance(resource.get("address"), str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource.get("type"), str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if resource.get("action") not in {"create", "update", "delete"}:
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource.get("labels"), dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if resource.get("secret") is not None and not isinstance(
        resource.get("secret"), str
    ):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource.get("forceDestroy"), bool):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    # 2. Environment
    if body["environment"] != TF_ENVIRONMENT:
        return jsonify({
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        })

    # 3. State
    if (
        state["backend"] not in VALID_BACKENDS
        or state["locked"] is not True
    ):
        return jsonify({
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        })

    # 4. Provider
    if body["providerVersion"] not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return jsonify({
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        })

    # 5. Labels
    labels = resource["labels"]

    for key, value in REQUIRED_LABELS.items():
        if labels.get(key) != value:
            return jsonify({
                "decision": "reject",
                "reason": "MISSING_LABELS"
            })

    # 6. Secret
    secret = resource["secret"]

    if secret is not None:
        if (
            not secret.startswith("secret://")
            or len(secret) == len("secret://")
        ):
            return jsonify({
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            })

    # 7. Delete approval
    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_TYPES
        and body["destroyApproved"] is not True
    ):
        return jsonify({
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        })

    # 8. Force destroy
    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return jsonify({
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        })

    return jsonify({
        "decision": "approve",
        "reason": "APPROVE"
    })


# ============================================================
# Q4 — SANITIZE OUTPUT
# ============================================================

ALLOWED_HOSTS = {
    "cdn-azl25lo.example",
    "app-aoe5bkg.example",
}


def decode_once(value):
    # Percent decode once.
    s = unquote(value)

    # Decode exactly the specified HTML entities.
    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    def entity_replace(match):
        token = match.group(0)

        low = token.lower()

        if low in entity_map:
            return entity_map[low]

        if low.startswith("&#x"):
            try:
                return chr(int(token[3:-1], 16))
            except ValueError:
                return token

        if low.startswith("&#"):
            try:
                return chr(int(token[2:-1], 10))
            except ValueError:
                return token

        return token

    s = re.sub(
        r"&(?:lt|gt|quot|apos|amp);|&#[0-9]+;|&#x[0-9a-fA-F]+;",
        entity_replace,
        s,
        flags=re.I,
    )

    # Decode \uXXXX once.
    s = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        s,
    )

    return s


def extract_html_urls(text):
    return [
        m.group(2)
        for m in re.finditer(
            r"""\b(?:src|href)\s*=\s*(["'])(.*?)\1""",
            text,
            re.I | re.S,
        )
    ]


def extract_markdown_urls(text):
    results = []

    for m in re.finditer(r"\]\(\s*([^)]+?)\s*\)", text):
        target = m.group(1).strip()

        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]

        # Markdown destination may contain an optional title.
        # The URL is the first token unless enclosed in <...>.
        if not target.startswith("<"):
            target = target.split(None, 1)[0]

        results.append(target)

    return results


def has_dangerous_scheme(text, urls):
    # Explicit dangerous schemes anywhere in the text.
    if re.search(
        r"(?:javascript|data|vbscript)\s*:",
        text,
        re.I,
    ):
        return True

    for url in urls:
        candidate = (
            "https:" + url
            if url.startswith("//")
            else url
        )

        parsed = urlparse(candidate)

        if parsed.scheme and parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            return True

    return False


def has_external_exfil(urls):
    for url in urls:
        url = url.strip()

        # Relative references are allowed.
        if url.startswith("/") and not url.startswith("//"):
            continue

        # Protocol-relative is absolute and resolved as HTTPS.
        candidate = (
            "https:" + url
            if url.startswith("//")
            else url
        )

        parsed = urlparse(candidate)

        if parsed.scheme.lower() in {"http", "https"}:
            if parsed.hostname not in ALLOWED_HOSTS:
                return True

    return False


def output_rule(channel, output):
    if channel == "html":
        if re.search(
            r"<\s*(script|iframe|object|embed)\b",
            output,
            re.I,
        ):
            return "SCRIPT_TAG"

        if re.search(
            r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
            output,
            re.I,
        ):
            return "EVENT_HANDLER"

        urls = extract_html_urls(output)

        if has_dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "markdown":
        urls = extract_markdown_urls(output)

        if has_dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "url":
        urls = [output.strip()]

        if has_dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "sql":
        if re.search(
            r"""['";]|--|/\*|\bunion\b|\bor\s+1=1\b""",
            output,
            re.I,
        ):
            return "SQL_METACHAR"

    elif channel == "shell":
        if re.search(
            r"[;&|`<>]|\$\(|\$\{",
            output,
        ):
            return "SHELL_METACHAR"

    return None


@app.post("/sanitize-output")
def sanitize_output():
    body = request.get_json(silent=True)

    # 1. Schema
    if not isinstance(body, dict):
        return jsonify({
            "safe": False,
            "reason": "INVALID_SCHEMA",
        })

    channel = body.get("channel")
    output = body.get("output")

    if channel not in {
        "html",
        "markdown",
        "url",
        "sql",
        "shell",
    }:
        return jsonify({
            "safe": False,
            "reason": "INVALID_SCHEMA",
        })

    if not isinstance(output, str):
        return jsonify({
            "safe": False,
            "reason": "INVALID_SCHEMA",
        })

    if len(output) > 20000:
        return jsonify({
            "safe": False,
            "reason": "INVALID_SCHEMA",
        })

    # 2. Decode once and see if decoded version triggers
    #    any of the channel rules.
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = output_rule(channel, decoded)

        if decoded_reason is not None:
            return jsonify({
                "safe": False,
                "reason": "ENCODED_PAYLOAD",
            })

    # 3. Original output
    reason = output_rule(channel, output)

    if reason is not None:
        return jsonify({
            "safe": False,
            "reason": reason,
        })

    return jsonify({
        "safe": True,
        "reason": "SAFE",
    })


# ============================================================
# Q5 — CORROBORATE
# ============================================================

VALID_SOURCE_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        text = value

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except Exception:
        return None


@app.post("/corroborate")
def corroborate():
    body = request.get_json(silent=True)

    # Rule 1
    if not isinstance(body, dict):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        })

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        })

    if not isinstance(claim.get("value"), str):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        })

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        })

    staleness = body.get("stalenessDays")

    if (
        not isinstance(staleness, (int, float))
        or isinstance(staleness, bool)
    ):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        })

    sources = body.get("sources")

    if not isinstance(sources, list):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": [],
        })

    claim_value = claim["value"]
    max_seconds = staleness * 86400

    fresh = []

    for source in sources:
        # Invalid sources are ignored entirely.
        if not isinstance(source, dict):
            continue

        if not isinstance(source.get("id"), str):
            continue

        if not isinstance(source.get("origin"), str):
            continue

        if not isinstance(source.get("value"), str):
            continue

        if not isinstance(source.get("observedAt"), str):
            continue

        if source.get("type") not in VALID_SOURCE_TYPES:
            continue

        observed = parse_timestamp(source["observedAt"])

        if observed is None:
            continue

        age = (as_of - observed).total_seconds()

        # Fresh means <= stalenessDays.
        if age <= max_seconds:
            fresh.append(source)

    # Rule 2: authoritative contradiction
    contradictions = []

    for source in fresh:
        if (
            source.get("authoritative") is True
            and source["value"] != claim_value
        ):
            contradictions.append(source["id"])

    if contradictions:
        return jsonify({
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradictions),
        })

    # Rule 3: matching sources
    matching = [
        source
        for source in fresh
        if source["value"] == claim_value
    ]

    representatives = {}

    for source in matching:
        origin = source["origin"]

        if (
            origin not in representatives
            or source["id"] < representatives[origin]["id"]
        ):
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:
        source_ids = sorted(source["id"] for source in reps)
        types = {source["type"] for source in reps}

        return jsonify({
            "verdict": "supported",
            "confidence": (
                "high"
                if len(types) >= 2
                else "medium"
            ),
            "corroboratingSources": source_ids,
        })

    # Rule 4
    return jsonify({
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    })


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
