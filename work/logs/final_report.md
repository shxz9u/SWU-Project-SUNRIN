# 라즈베리파이-클라우드 연계형 IoT 취약점 분석 시스템

## Environment Summary

- Generated At: 2026-06-27T06:29:40.363169+00:00
- Platform: Linux-6.17.0-35-generic-x86_64-with-glibc2.41
- Python: 3.11.15
- Target Source: /work/target/input.c
- Target Binary: /work/target/target_binary
- Input Mode: stdin
- Ollama Base URL: http://210.110.103.200:11434
- Ollama Model: gemma4

## LLM Candidate Summary

- Status: OK
- Candidate Count: 6
- Duration Seconds: 36.130815

| Candidate ID | Status | Type | Function | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| LLM-001 | CONFIRMED | buffer_overflow | parse_config_line | high | strcpy(ssid_tmp, value); |
| LLM-002 | CONFIRMED | buffer_overflow | parse_config_line | high | strcpy(password_tmp, value); |
| LLM-003 | CONFIRMED | buffer_overflow | parse_config_line | high | strcat(config->topic, value); |
| LLM-004 | FALSE_POSITIVE | format_string | parse_config_line | high | printf(value); |
| LLM-005 | FALSE_POSITIVE | hardcoded_credentials | parse_config_line | medium | #define ADMIN_USER "admin" #define ADMIN_PASSWORD "sunrin_admin123" |
| LLM-006 | FALSE_POSITIVE | command_injection_risk | parse_config_line | medium | snprintf(command, sizeof(command), "ubus call gateway.%s", value); |

## Fuzzing Summary

- Status: OK
- Total Runs: 200
- Suspicious Findings: 33
- Crash Count: 0
- Timeout Count: 0
- Sanitizer Error Count: 35
- Abnormal Exit Count: 0
- Duration Seconds: 0.997968

## Verification Summary

- Status: OK
- Verification Runs Per Finding: 3
- Confirmation Threshold: 2
- Confirmed Finding Count: 33
- Confirmed LLM Candidate Count: 3
- Not Reproduced Count: 0
- Duration Seconds: 0.681558

## Metrics

| Metric | Value |
| --- | --- |
| Detection Rate | 83.33% |
| Verification Success Rate | 50.00% |
| False Positive Rate | 50.00% |
| Total Time | 38.006115 seconds |

## Final Classification Table

| Finding ID | Source | Status | Issue Type | Reproduced | Input |
| --- | --- | --- | --- | --- | --- |
| LLM-001 | LLM | CONFIRMED | buffer_overflow | N/A | N/A |
| LLM-002 | LLM | CONFIRMED | buffer_overflow | N/A | N/A |
| LLM-003 | LLM | CONFIRMED | buffer_overflow | N/A | N/A |
| LLM-004 | LLM | FALSE_POSITIVE | format_string | N/A | N/A |
| LLM-005 | LLM | FALSE_POSITIVE | hardcoded_credentials | N/A | N/A |
| LLM-006 | LLM | FALSE_POSITIVE | command_injection_risk | N/A | N/A |
| FUZZ-001 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-001_sanitizer_error.input |
| FUZZ-002 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-002_sanitizer_error.input |
| FUZZ-003 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-003_sanitizer_error.input |
| FUZZ-004 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-004_sanitizer_error.input |
| FUZZ-005 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-005_sanitizer_error.input |
| FUZZ-006 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-006_sanitizer_error.input |
| FUZZ-007 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-007_sanitizer_error.input |
| FUZZ-008 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-008_sanitizer_error.input |
| FUZZ-009 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-009_sanitizer_error.input |
| FUZZ-010 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-010_sanitizer_error.input |
| FUZZ-011 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-011_sanitizer_error.input |
| FUZZ-012 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-012_sanitizer_error.input |
| FUZZ-013 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-013_sanitizer_error.input |
| FUZZ-014 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-014_sanitizer_error.input |
| FUZZ-015 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-015_sanitizer_error.input |
| FUZZ-016 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-016_sanitizer_error.input |
| FUZZ-017 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-017_sanitizer_error.input |
| FUZZ-018 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-018_sanitizer_error.input |
| FUZZ-019 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-019_sanitizer_error.input |
| FUZZ-020 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-020_sanitizer_error.input |
| FUZZ-021 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-021_sanitizer_error.input |
| FUZZ-022 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-022_sanitizer_error.input |
| FUZZ-023 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-023_sanitizer_error.input |
| FUZZ-024 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-024_sanitizer_error.input |
| FUZZ-025 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-025_sanitizer_error.input |
| FUZZ-026 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-026_sanitizer_error.input |
| FUZZ-027 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-027_sanitizer_error.input |
| FUZZ-028 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-028_sanitizer_error.input |
| FUZZ-029 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-029_sanitizer_error.input |
| FUZZ-030 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-030_sanitizer_error.input |
| FUZZ-031 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-031_sanitizer_error.input |
| FUZZ-032 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-032_sanitizer_error.input |
| FUZZ-033 | Fuzzing | CONFIRMED | sanitizer_error | 3/3 | /work/crashes/FUZZ-033_sanitizer_error.input |

## Ground Truth

| ID | Type | Function | Expected Evidence |
| --- | --- | --- | --- |
| GT-001 | buffer_overflow | parse_config_line | strcpy(ssid_tmp, value) copies ssid without length validation |
| GT-002 | buffer_overflow | parse_config_line | strcpy(password_tmp, value) copies password without length validation |
| GT-003 | buffer_overflow | parse_config_line | strcat(config->topic, value) appends topic without bounds checking |
| GT-004 | format_string | parse_config_line | printf(value) uses user-controlled log text as a format string |
| GT-005 | hardcoded_credentials | parse_config_line | ADMIN_USER and ADMIN_PASSWORD are compiled into the binary |
| GT-006 | missing_input_validation | parse_config_line | atoi(value) accepts port without numeric range validation |

## Observations

- LLM output is not treated as a final vulnerability.
- Only reproducible execution evidence is eligible for CONFIRMED status.
- LLM candidates are confirmed only when a reproduced finding is linked to an LLM-generated seed.

## Limitations

- This MVP uses mutation fuzzing only; it does not collect coverage.
- Candidate-to-finding linkage is seed-based, not code-location based.
- Resource usage metrics are not implemented yet.

## Next Steps

- Add resource usage logging for CPU and memory metrics.
- Add target-specific execution mode configuration for firmware-style programs.
- Replace the sample target with an authorized firmware component when selected.
