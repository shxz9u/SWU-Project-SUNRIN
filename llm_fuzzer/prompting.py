from __future__ import annotations

import json
from typing import Any


def build_fuzzing_prompt(scan_result: dict[str, Any], max_cases: int) -> str:
    scan_json = json.dumps(scan_result, ensure_ascii=False, indent=2)
    return f"""
You are an IoT security test-case generator for an authorized lab environment.
Use the scan result JSON to propose conservative fuzzing test cases.

Rules:
- Return JSON only.
- Do not include explanations outside JSON.
- Prefer low-impact malformed input, boundary values, protocol oddities, and auth/config checks.
- Do not generate destructive payloads, credential theft, persistence, malware, or denial-of-service floods.
- Limit the output to at most {max_cases} test cases.

Required JSON schema:
{{
  "target_summary": "short summary",
  "risk_hypotheses": [
    {{
      "category": "http|serial|mqtt|unknown",
      "risk": "low|medium|high",
      "evidence": "evidence from input JSON",
      "reason": "why this should be tested"
    }}
  ],
  "test_cases": [
    {{
      "id": "case-001",
      "interface": "http|serial|mqtt",
      "method": "GET|POST|SERIAL_WRITE",
      "path": "/optional-http-path",
      "headers": {{"Header-Name": "value"}},
      "body": "optional body string",
      "payload": "main payload or command",
      "expected_signal": "status change, error message, timeout, reboot log, or unusual response",
      "severity_if_confirmed": "low|medium|high"
    }}
  ]
}}

Scan result JSON:
{scan_json}
""".strip()

