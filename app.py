from flask import Flask, request, jsonify
from urllib.parse import unquote, urlparse
from html import unescape
from datetime import datetime, timezone
import re

app = Flask(__name__)


# ============================================================
# QUESTION 1 — /release-gate
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

    violations = []

    if not isinstance(body, dict):
        return jsonify({
            "decision": "block",
            "violations": [
                "EXCESS_PERMISSION",
                "UNSAFE_PR_TRIGGER",
                "TESTS_INCOMPLETE",
                "SINGLE_STAGE_IMAGE",
                "ROOT_RUNTIME",
                "SECRET_IN_LAYER",
                "CRITICAL_CVE",
                "UNPINNED_IMAGE"
            ]
        })

    workflow = body.get("workflow", {})
    image = body.get("image", {})

    # Permissions
    if workflow.get("permissions") != EXPECTED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # PR requirements
    if body.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        if (
            workflow.get("testsPassed") is not True
            or workflow.get("matrixComplete") is not True
            or workflow.get("failFast") is not False
        ):
            violations.append("TESTS_INCOMPLETE")

    # Actions
    for action in workflow.get("actions", []):
        if not isinstance(action, dict):
            violations.append("MUTABLE_ACTION")
            continue

        if action.get("owner") == "actions":
            continue

        ref = action.get("ref")

        if not isinstance(ref, str) or SHA40.fullmatch(ref) is None:
            violations.append("MUTABLE_ACTION")

    # Image
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
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
# QUESTION 2 — /action-firewall
# ============================================================

TENANT = "tenant-36k4fs9"
EMAIL_DOMAIN = "notify-rmnhsv9.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html"
}


def html_is_unsafe(value):
    if re.search(
        r"<\s*(script|iframe|object|embed)\b",
        value,
        re.I
    ):
        return True

    if re.search(
        r"\bon[a-zA-Z0-9_-]+\s*=",
        value,
        re.I
    ):
        return True

    if re.search(
        r"javascript\s*:|vbscript\s*:|data\s*:",
        value,
        re.I
    ):
        return True

    return False


@app.post("/action-firewall")
def action_firewall():
    body = request.get_json(silent=True)

    # 1. Top-level schema
    if not isinstance(body, dict):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if body.get("provenance") not in {"trusted", "untrusted"}:
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if not isinstance(body.get("humanApproved"), bool):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if "untrustedContent" in body and not isinstance(
        body["untrustedContent"], str
    ):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    action = body.get("action")

    if (
        not isinstance(action, dict)
        or set(action.keys()) != {"tool", "args"}
        or not isinstance(action.get("tool"), str)
        or not isinstance(action.get("args"), dict)
    ):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    tool = action["tool"]
    args = action["args"]

    # 2. Tool allowlist
    if tool not in ALLOWED_TOOLS:
        return jsonify({
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        })

    # 3. Tool argument schemas

    if tool == "search":
        if (
            set(args.keys()) != {"query"}
            or not isinstance(args["query"], str)
            or not 1 <= len(args["query"]) <= 200
        ):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if (
            not isinstance(args["tenantId"], str)
            or not isinstance(args["recordId"], str)
            or args["recordId"] == ""
        ):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        # 4. Tenant scope
        if args["tenantId"] != TENANT:
            return jsonify({
                "decision": "block",
                "reason": "TENANT_SCOPE"
            })

    elif tool == "send_email":
        if (
            set(args.keys()) != {"to", "subject", "body"}
            or not isinstance(args["to"], str)
            or not isinstance(args["subject"], str)
            or not isinstance(args["body"], str)
        ):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        # 5. Egress
        if "@" not in args["to"]:
            return jsonify({
                "decision": "block",
                "reason": "EGRESS_DENIED"
            })

        domain = args["to"].rsplit("@", 1)[1]

        if domain != EMAIL_DOMAIN:
            return jsonify({
                "decision": "block",
                "reason": "EGRESS_DENIED"
            })

        # 6. Approval
        if body["humanApproved"] is not True:
            return jsonify({
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            })

    elif tool == "render_html":
        if (
            set(args.keys()) != {"html"}
            or not isinstance(args["html"], str)
        ):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        # 7. HTML safety
        if html_is_unsafe(args["html"]):
            return jsonify({
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            })

    return jsonify({
        "decision": "allow",
        "reason": "ALLOW"
    })


# ============================================================
# QUESTION 3 — /terraform/plan
# ============================================================

TF_ENVIRONMENT = "prod-4tx5cu"

REQUIRED_LABELS = {
    "owner": "student-b2diq",
    "environment": "production",
    "cost_center": "cc-0zts"
}

VALID_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote"
}

DESTRUCTIVE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk"
}


@app.post("/terraform/plan")
def terraform_plan():
    body = request.get_json(silent=True)

    # 1. Basic schema
    if not isinstance(body, dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    required = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource"
    }

    if set(body.keys()) != required:
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if (
        not isinstance(body["environment"], str)
        or not isinstance(body["state"], dict)
        or not isinstance(body["providerVersion"], str)
        or not isinstance(body["destroyApproved"], bool)
        or not isinstance(body["resource"], dict)
    ):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    state = body["state"]

    if (
        set(state.keys()) != {"backend", "locked"}
        or not isinstance(state["backend"], str)
        or not isinstance(state["locked"], bool)
    ):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    resource = body["resource"]

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy"
    }

    if set(resource.keys()) != required_resource:
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if (
        not isinstance(resource["address"], str)
        or not isinstance(resource["type"], str)
        or resource["action"] not in {"create", "update", "delete"}
        or not isinstance(resource["labels"], dict)
        or not isinstance(resource["forceDestroy"], bool)
        or (
            resource["secret"] is not None
            and not isinstance(resource["secret"], str)
        )
    ):
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

    # 4. Provider pinning
    if body["providerVersion"] not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0"
    }:
        return jsonify({
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        })

    # 5. Labels
    for key, expected in REQUIRED_LABELS.items():
        if resource["labels"].get(key) != expected:
            return jsonify({
                "decision": "reject",
                "reason": "MISSING_LABELS"
            })

    # 6. Secret
    secret = resource["secret"]

    if secret is not None:
        if not (
            secret.startswith("secret://")
            and len(secret) > len("secret://")
        ):
            return jsonify({
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            })

    # 7. Destructive delete
    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_TYPES
        and body["destroyApproved"] is not True
    ):
        return jsonify({
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        })

    # 8. Production bucket forceDestroy
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
# QUESTION 4 — /sanitize-output
# ============================================================

ALLOWED_HOSTS = {
    "cdn-azl25lo.example",
    "app-aoe5bkg.example"
}


def decode_once(value):
    # Percent escapes
    result = unquote(value)

    # Requested HTML entities
    result = re.sub(
        r"&(?:lt|gt|quot|apos|amp);|&#[0-9]+;|&#x[0-9a-fA-F]+;",
        lambda m: (
            unescape(m.group(0))
            if not m.group(0).lower().startswith("&#")
            else (
                chr(int(m.group(0)[2:-1]))
                if m.group(0).lower().startswith("&#x") is False
                else chr(int(m.group(0)[3:-1], 16))
            )
        ),
        result,
        flags=re.I
    )

    # \uXXXX
    result = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        result
    )

    return result


def extract_html_urls(value):
    return [
        m.group(2)
        for m in re.finditer(
            r"""\b(?:src|href)\s*=\s*(["'])(.*?)\1""",
            value,
            re.I | re.S
        )
    ]


def extract_markdown_urls(value):
    return [
        m.group(1)
        for m in re.finditer(
            r"\]\(\s*<?([^>\s)]+)>?",
            value
        )
    ]


def dangerous_scheme(value, urls):
    if re.search(
        r"(?:javascript|data|vbscript)\s*:",
        value,
        re.I
    ):
        return True

    for url in urls:
        candidate = "https:" + url if url.startswith("//") else url
        scheme = urlparse(candidate).scheme.lower()

        if scheme and scheme not in {"http", "https"}:
            return True

    return False


def external_exfil(urls):
    for url in urls:
        # Relative URL
        if url.startswith("/") and not url.startswith("//"):
            continue

        candidate = "https:" + url if url.startswith("//") else url
        parsed = urlparse(candidate)

        if parsed.scheme in {"http", "https"}:
            if parsed.hostname not in ALLOWED_HOSTS:
                return True

    return False


def sanitize_decoded(channel, output):
    if channel == "html":
        if re.search(
            r"<\s*(script|iframe|object|embed)\b",
            output,
            re.I
        ):
            return "SCRIPT_TAG"

        if re.search(
            r"\bon[a-zA-Z0-9_-]+\s*=",
            output,
            re.I
        ):
            return "EVENT_HANDLER"

        urls = extract_html_urls(output)

        if dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"

        if external_exfil(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "markdown":
        urls = extract_markdown_urls(output)

        if dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"

        if external_exfil(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "url":
        urls = [output.strip()]

        if dangerous_scheme(output, urls):
            return "DANGEROUS_SCHEME"

        if external_exfil(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "sql":
        if re.search(
            r"""['";]|--|/\*|\bunion\b|\bor\s+1=1\b""",
            output,
            re.I
        ):
            return "SQL_METACHAR"

    elif channel == "shell":
        if re.search(
            r"""[;&|`<>]|\$\(|\$\{""",
            output
        ):
            return "SHELL_METACHAR"

    return None


@app.post("/sanitize-output")
def sanitize_output():
    body = request.get_json(silent=True)

    # 1. Schema
    if (
        not isinstance(body, dict)
        or set(body.keys()) != {"channel", "output"}
        or body.get("channel") not in {
            "html",
            "markdown",
            "url",
            "sql",
            "shell"
        }
        or not isinstance(body.get("output"), str)
        or len(body["output"]) > 20000
    ):
        return jsonify({
            "safe": False,
            "reason": "INVALID_SCHEMA"
        })

    channel = body["channel"]
    output = body["output"]

    # 2. Decode once and test decoded payload.
    decoded = decode_once(output)

    if decoded != output:
        if sanitize_decoded(channel, decoded) is not None:
            return jsonify({
                "safe": False,
                "reason": "ENCODED_PAYLOAD"
            })

    # 3. Test original
    reason = sanitize_decoded(channel, output)

    if reason:
        return jsonify({
            "safe": False,
            "reason": reason
        })

    return jsonify({
        "safe": True,
        "reason": "SAFE"
    })


# ============================================================
# QUESTION 5 — /corroborate
# ============================================================

VALID_SOURCE_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan"
}


def parse_time(value):
    if not isinstance(value, str):
        return None

    try:
        value = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except Exception:
        return None


@app.post("/corroborate")
def corroborate():
    body = request.get_json(silent=True)

    # 1. Invalid
    if not isinstance(body, dict):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    claim = body.get("claim")

    if (
        not isinstance(claim, dict)
        or not isinstance(claim.get("value"), str)
    ):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    as_of = parse_time(body.get("asOf"))

    if as_of is None:
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    if (
        not isinstance(body.get("stalenessDays"), (int, float))
        or isinstance(body.get("stalenessDays"), bool)
    ):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    if not isinstance(body.get("sources"), list):
        return jsonify({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    claim_value = claim["value"]
    max_age = body["stalenessDays"] * 86400

    valid_sources = []

    for source in body["sources"]:
        if not isinstance(source, dict):
            continue

        if not (
            isinstance(source.get("id"), str)
            and isinstance(source.get("origin"), str)
            and isinstance(source.get("value"), str)
            and isinstance(source.get("observedAt"), str)
            and source.get("type") in VALID_SOURCE_TYPES
        ):
            continue

        observed = parse_time(source["observedAt"])

        if observed is None:
            continue

        authoritative = source.get("authoritative", False)

        if not isinstance(authoritative, bool):
            authoritative = False

        age = (as_of - observed).total_seconds()

        if age <= max_age:
            valid_sources.append({
                "id": source["id"],
                "origin": source["origin"],
                "value": source["value"],
                "type": source["type"],
                "authoritative": authoritative
            })

    # 2. Fresh authoritative contradiction
    contradicting = [
        s for s in valid_sources
        if s["authoritative"] and s["value"] != claim_value
    ]

    if contradicting:
        return jsonify({
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(
                s["id"] for s in contradicting
            )
        })

    # 3. Fresh matching sources
    matching = [
        s for s in valid_sources
        if s["value"] == claim_value
    ]

    # One representative per origin, smallest ID.
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
        types = {s["type"] for s in reps}

        return jsonify({
            "verdict": "supported",
            "confidence": "high" if len(types) >= 2 else "medium",
            "corroboratingSources": sorted(
                s["id"] for s in reps
            )
        })

    # 4. Everything else
    return jsonify({
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    })


# ============================================================
# Health endpoint
# ============================================================

@app.get("/")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
