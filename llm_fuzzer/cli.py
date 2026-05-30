from __future__ import annotations

import argparse
import datetime as dt
import sys
from typing import Any

from .http_runner import run_http_case
from .json_utils import load_json_file, parse_json_object, write_json_file
from .ollama_client import OllamaError, generate
from .prompting import build_fuzzing_prompt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate and optionally run LLM-guided IoT fuzzing test cases."
    )
    parser.add_argument("--input", required=True, help="scan result JSON file")
    parser.add_argument("--output", required=True, help="output JSON file")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="gemma4")
    parser.add_argument("--max-cases", type=int, default=8)
    parser.add_argument("--execute-http", action="store_true")
    parser.add_argument("--target-base-url", help="base URL for executing HTTP cases")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="required when executing generated test cases",
    )
    args = parser.parse_args(argv)

    try:
        scan_result = load_json_file(args.input)
        prompt = build_fuzzing_prompt(scan_result, args.max_cases)
        llm_text = generate(prompt, base_url=args.ollama_url, model=args.model)
        plan = parse_json_object(llm_text)
    except (OllamaError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    result: dict[str, Any] = {
        "metadata": {
            "tool": "llm_fuzzer",
            "model": args.model,
            "ollama_url": args.ollama_url,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "executed_http": False,
        },
        "scan_input": scan_result,
        "llm_plan": plan,
        "execution_results": [],
    }

    if args.execute_http:
        if not args.i_have_authorization:
            print("error: --execute-http requires --i-have-authorization", file=sys.stderr)
            return 2
        if not args.target_base_url:
            print("error: --execute-http requires --target-base-url", file=sys.stderr)
            return 2

        cases = plan.get("test_cases", [])
        if not isinstance(cases, list):
            print("error: llm_plan.test_cases must be a list", file=sys.stderr)
            return 1

        result["metadata"]["executed_http"] = True
        for case in cases:
            if isinstance(case, dict) and case.get("interface") == "http":
                result["execution_results"].append(
                    run_http_case(args.target_base_url, case, args.timeout)
                )

    write_json_file(args.output, result)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

