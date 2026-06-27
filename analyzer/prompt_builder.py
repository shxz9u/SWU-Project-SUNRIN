from pathlib import Path


VULNERABILITY_TYPES = (
    "buffer_overflow",
    "unsafe_function_usage",
    "format_string",
    "command_injection_risk",
    "hardcoded_credentials",
    "missing_input_validation",
    "memory_safety_issue",
)


def build_vulnerability_prompt(source_path: Path, source_text: str) -> str:
    joined_types = ", ".join(VULNERABILITY_TYPES)
    return f"""You are analyzing a controlled educational IoT C target.
Return only valid JSON. Do not include Markdown fences or commentary.

The LLM output is not a final vulnerability finding. It will be used only to
generate fuzzing seeds. Final classification will be based on crash, timeout,
sanitizer error, abnormal exit code, and reproducibility.

Focus on these vulnerability types:
{joined_types}

Return JSON in this exact shape:
{{
  "candidates": [
    {{
      "candidate_id": "LLM-001",
      "vulnerability_type": "buffer_overflow",
      "file": "{source_path.name}",
      "function": "parse_config_line",
      "reason": "Unsafe copy without length validation",
      "evidence": "strcpy(dst, input)",
      "suggested_seeds": [
        "ssid=normal",
        "ssid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "log=%x%x%x%x"
      ],
      "confidence": "medium",
      "status": "LLM_CANDIDATE"
    }}
  ]
}}

Seed requirements:
- suggested_seeds must be complete stdin inputs for the program.
- Prefer firmware/config-style lines such as ssid=..., password=..., log=..., cmd=....
- Include boundary-length, long-string, format-string, and shell-metacharacter examples when relevant.
- Do not use string concatenation, repeat(), comments, or any non-JSON expression.
- Do not include destructive commands. Use harmless markers such as ;id or ;echo test.
- Keep candidates concise and avoid duplicates.

Source file: {source_path.name}

```c
{source_text}
```
"""
