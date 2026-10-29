"""All report text is data; HTML has no executable or remote content."""

import base64
import hashlib
import html
import json

STYLE = """
body{font:16px/1.5 system-ui,sans-serif;color:#17283a;background:#f6f8fa;margin:0}
main{max-width:1100px;margin:auto;padding:2rem}h1{font-size:2rem;line-height:1.2}
h2{margin-top:2rem}h3{margin-top:0}section,.notice{background:white;border:1px solid
#cbd5df;border-radius:.5rem;padding:1rem;margin:1rem 0}table{border-collapse:collapse;
width:100%;margin:1rem 0}th,td{border-bottom:1px solid #cbd5df;padding:.5rem;text-align:
left;vertical-align:top;overflow-wrap:anywhere}th{font-weight:600}pre{white-space:
pre-wrap;overflow-wrap:anywhere;font-size:.85rem}code{overflow-wrap:anywhere}
summary{cursor:pointer;font-weight:600}caption{text-align:left;font-weight:600}
.scroll{overflow:auto}.notice{border-left:5px solid #476b8f}
.statistics{min-width:36rem}.statistics td:nth-child(n+2){white-space:nowrap}
@media print{body{background:white}main{padding:0}section{break-inside:avoid}}
""".strip()


def _text(value) -> str:
    return html.escape("Unknown" if value is None else str(value), quote=True)


def _table(caption, headers, rows) -> str:
    return (
        '<div class="scroll"><table'
        + (' class="statistics"' if len(headers) == 5 else "")
        + "><caption>"
        + _text(caption)
        + "</caption><thead><tr>"
        + "".join('<th scope="col">' + _text(header) + "</th>" for header in headers)
        + "</tr></thead><tbody>"
        + "".join(
            "<tr>" + "".join("<td>" + _text(cell) + "</td>" for cell in row) + "</tr>"
            for row in rows
        )
        + "</tbody></table></div>"
    )


def _joined(values) -> str:
    return ", ".join(map(str, values)) if values else "None recorded"


def _readable(report: dict) -> str:
    parsed, coverage = report["parse"], report["coverage"]
    body = "<h1>Firewall traffic observations</h1>"
    body += (
        '<div class="notice"><strong>NOT APPLIED — proposals require human review.</strong>'
        "<p>Flags are observations, not attack proof. Empty results do not establish "
        "benign traffic. Partial and suppressed groups remain visible.</p></div>"
    )
    body += "<h2>Input and coverage</h2>"
    body += _table(
        "Analysis snapshot",
        ("Field", "Recorded value"),
        [
            ("Physical parse", parsed["state"]),
            ("Original candidate rows", parsed["original_rows"]),
            ("Processed rows", parsed["processed_rows"]),
            ("Quarantined rows", parsed["quarantined_rows"]),
            ("Excluded rows", parsed["excluded_rows"]),
            ("Parse reasons", _joined(parsed["reason_codes"])),
            ("Source SHA256", parsed["source_sha256"]),
            ("Parser profile", report["parser_profile_version"]),
            ("Direction", report["direction_status"]),
            ("Configuration SHA256", report["config_sha256"]),
            ("As-of UTC microseconds", report["settings"]["as_of_us"]),
            ("Checked explanation groups", f"{coverage['verified_groups']} / {coverage['groups']}"),
            (
                "Explanation coverage fraction",
                "N/A — no groups" if coverage["groups"] == 0 else coverage["verified_fraction"],
            ),
            ("Coverage meaning", coverage["meaning"]),
            ("Canonical row citation status", report["canonical_citations"]["status"]),
            (
                "Canonical resolved / required physical rows",
                f"{report['canonical_citations']['resolved_rows']} / "
                f"{report['canonical_citations']['required_rows']}",
            ),
            ("Quality evaluation", report["quality_evaluation"]),
            (
                "Live providers",
                "Disabled"
                if report["providers_available"] is False
                else report["providers_available"],
            ),
        ],
    )
    body += "<h2>Rule channels</h2>"
    body += _table(
        "Capability and completeness",
        ("Rule", "Status", "Reasons"),
        [
            (channel["rule_id"], channel["status"], _joined(channel["reason_codes"]))
            for channel in report["channels"]
        ],
    )
    body += "<h2>Observed groups</h2>"
    if not report["groups"]:
        body += "<p>No groups produced. Explanation coverage is N/A.</p>"
    for index, item in enumerate(report["groups"], start=1):
        group, explanation, proposal = item["group"], item["explanation"], item["proposal"]
        body += f'<section aria-labelledby="group-{index}"><h3 id="group-{index}">'
        body += f"{index}. {_text(group['rule_id'])} — {_text(group['status'])}</h3>"
        body += _table(
            "Group identity and scope",
            ("Field", "Recorded value"),
            [
                ("Group SHA256", group["group_id"]),
                ("Rule version", group["rule_version"]),
                ("Category from rule", group["category_from_rule"]),
                ("Severity from rule (1–4)", group["severity_from_rule"]),
                (
                    "Subject",
                    "; ".join(f"{part['name']}={part['value']}" for part in group["grouping_key"]),
                ),
                (
                    "Window UTC microseconds [start, end)",
                    f"[{group['window']['start_us']}, {group['window']['end_us']})",
                ),
                ("Full supporting rows", len(group["support"]["row_ids"])),
                ("Support SHA256", group["support"]["support_sha256"]),
                ("Matched contexts", _joined(group["matched_context_ids"])),
                ("Quality flags", _joined(group["quality_flags"])),
            ],
        )
        body += _table(
            "Computed observations",
            ("Statistic", "Value", "Unit", "Known", "Unknown"),
            [
                (
                    stat["stat_id"],
                    stat["value"],
                    stat["unit"],
                    stat["known_count"],
                    stat["unknown_count"],
                )
                for stat in group["stats"]
            ],
        )
        body += "<h4>Source-checked explanation: " + _text(explanation["state"]) + "</h4>"
        body += "<p>Reasons: " + _text(_joined(explanation["reason_codes"])) + "</p><ul>"
        body += "".join(
            "<li><strong>"
            + _text(sentence["label_kind"])
            + "</strong>: "
            + _text(sentence["text"])
            + "</li>"
            for sentence in explanation["sentences"]
        )
        body += "</ul><h4>Human review proposal: " + _text(proposal["status"]) + "</h4>"
        body += "<pre>" + _text(proposal["text"]) + "</pre>"
        body += "<p>Reasons: " + _text(_joined(proposal["reason_codes"])) + "</p></section>"
    body += "<h2>Limits and audit</h2><ul>"
    body += "".join("<li>" + _text(line) + "</li>" for line in report["limitations"])
    body += (
        "</ul><p>Full supporting raw row bytes are in evidence.json. The complete report "
        "below retains all support IDs, checked claim references and recorded settings. "
        "The adjacent manifest is a hash inventory, not a signature or policy approval. "
        "Verification requires the caller's explicit original source.</p>"
        "<details><summary>Complete recorded report JSON</summary><pre>"
    )
    return body + _text(json_bytes(report).decode()) + "</pre></details>"


def json_bytes(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    ).encode()


def render(report: dict) -> dict[str, bytes]:
    # Shared semantic HTML also works in Markdown readers supporting embedded HTML.
    # All dynamic content is escaped as text; no dynamic attributes or destinations.
    body = _readable(report)
    markdown = body + "\n"
    style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        f"content=\"default-src 'none'; base-uri 'none'; form-action 'none'; "
        f"style-src 'sha256-{style_hash}'\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Firewall traffic observations</title><style>{STYLE}</style><body><main>"
        + body
        + "</main></body></html>\n"
    )
    proposals = "\n\n".join(item["proposal"]["text"] for item in report["groups"])
    if not proposals:
        proposals = "NOT APPLIED — no rule proposal produced. This is not an attack-free finding."
    return {
        "report.json": json_bytes(report),
        "report.md": markdown.encode(),
        "report.html": page.encode(),
        "proposed-rules.txt": (proposals + "\n").encode(),
    }
