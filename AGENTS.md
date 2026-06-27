# AGENTS.md

## Project Overview

This project is titled:

**라즈베리파이-클라우드 연계형 IoT 취약점 분석 시스템**

The original project concept is to build a Raspberry Pi-based IoT vulnerability analysis gateway that collects target data, sends analysis requests to a cloud/local LLM, runs fuzzing, and compares the results.

Current team information from the project slide:

* Team: 3팀
* Members: 유승주, 김주한, 이지한, 박현우
* Main technologies: Python, Raspberry Pi, Cloud LLM, Docker, Fuzzing
* Current environment: Linux Host PC + Docker container
* Current LLM runtime: Ollama Gemma4 running on the Linux host

The current implementation does not use a physical Raspberry Pi yet. Instead, a Docker container acts as the **Raspberry Pi analysis gateway**.

This Docker gateway is not a full Raspberry Pi hardware emulator. It is a software replacement for the Pi's expected role:

* collect target files/logs
* execute analysis scripts
* run fuzzingboo
* collect crash/resource logs
* call the host LLM API
* save comparison results

Physical Raspberry Pi deployment can be added later.

---

## Research Direction

The project should focus on **IoT firmware / C language vulnerability analysis**, not general web application vulnerability scanning.

Preferred vulnerability types:

* Buffer Overflow
* Unsafe Function Usage
* Format String Bug
* Command Injection Risk
* Hardcoded Credentials
* Missing Input Validation
* Memory Safety Issues
* Firmware configuration weaknesses

The first MVP target may be a sample C file and local binary. The real firmware target can be selected later.

Potential future targets:

* DVRF
* OWASP IoTGoat
* Open-source C firmware components
* Small intentionally vulnerable C programs
* QEMU-based firmware emulation targets

Do not assume a final target firmware yet unless the user explicitly decides one.

---

## Core Pipeline

The pipeline must follow this structure:

```text
LLM Analysis → Fuzzing Seed Generation → Fuzzing Execution → Verification → Final Classification
```

Important rule:

**LLM output is never a final vulnerability finding.**

The LLM is only used to produce:

* vulnerability candidates
* suspicious functions
* reasoning
* fuzzing seed ideas
* expected input conditions

Final vulnerability classification must be based on execution evidence:

* crash
* timeout
* sanitizer error
* abnormal exit code
* reproducible behavior

---

## Current Architecture

```text
[Linux Host PC]
├── Ollama
│   └── Gemma4 model
│
└── Docker Container: pi-gateway
    ├── Reads C source / binary / target files
    ├── Calls Host Ollama API
    ├── Generates LLM vulnerability candidates
    ├── Generates fuzzing seeds
    ├── Runs simple mutation fuzzing
    ├── Collects crash / timeout / sanitizer logs
    ├── Verifies reproducibility
    └── Writes JSON and Markdown reports
```

The Docker container should connect to the host Ollama API.

For Linux, use:

```yaml
network_mode: "host"
```

Default Ollama API URL:

```text
http://127.0.0.1:11434
```

Required environment variables:

```text
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=gemma4
WORK_DIR=/work
```

---

## Implementation Priority

The current priority is not the final firmware target.

The current priority is:

```text
1. Create Docker-based Raspberry Pi gateway container
2. Confirm the container can access Host Ollama API
3. Prepare project directory structure
4. Read a sample C file from /work/target/input.c
5. Ask Ollama Gemma4 for vulnerability candidates
6. Save LLM candidate results
7. Generate fuzzing seeds
8. Run simple fuzzing against a compiled local binary
9. Verify crashes or sanitizer errors
10. Generate final reports
```

Do not jump directly to QEMU, AFL++, or real firmware analysis unless the user explicitly asks.

---

## PPT-Based Today Goal

The slide defined today's goal as:

```text
수집 → 분석 → 비교 1회전 완성
```

Meaning:

For one target, run both:

* Cloud/Local LLM analysis
* Fuzzing-based detection

Then create a first draft comparison table using 4 metrics.

The slide says:

```text
대상 1개에 대해 클라우드 LLM 분석과 Fuzzing 탐지를 각각 돌려,
4개 지표 비교표 초안까지 만들기
```

In the current revised architecture, this becomes:

```text
대상 1개에 대해 LLM 후보 분석 → Fuzzing 실행 → 검증까지 수행하고,
탐지율 / 검증 성공률 / 소요 시간 / 오탐률 기준으로 비교표 초안을 만든다.
```

---

## PPT-Based 3-Hour Timeline

The project slide defines a 3-hour afternoon session.

### Block 1: 0:00–0:30 — Architecture & Evaluation Design

Original slide content:

* 하이브리드 구조 확정
* 대상 및 정답셋 선정
* 4개 지표 측정법 정의

Detailed slide content:

* 하이브리드 구조 확정

  * Pi = 경량 수집 게이트웨이
  * 외부/클라우드 LLM = 무거운 분석
* 대상 1개 선정

  * 알려진 취약점 보유 서비스로 정답셋 확보
  * 탐지율 및 오탐 계산 가능해야 함
* 4개 지표 측정법 확정
* 역할 분담

Expected output:

```text
데이터 흐름도 + 지표 정의표 + 역할표
```

Current interpretation:

* Physical Pi is replaced by Docker `pi-gateway`
* LLM runs on Linux host through Ollama Gemma4
* Docker container performs collection, fuzzing, verification, and logging
* Final target can be selected later
* Evaluation metrics are defined before implementation

---

### Block 2: 0:30–1:30 — Collection Gateway + Target Preparation

Original slide content:

* Pi 또는 에뮬레이터에서 IoT 연결
* 트래픽 수집
* 리소스 베이스라인

Detailed slide content:

* Pi 또는 Docker emulator connects to target
* Collect traffic for one protocol such as MQTT or HTTP
* Standardize artifacts to pass into analysis:

  * pcap
  * request/response logs
  * firmware files
  * configuration files
* Measure Pi resource baseline:

  * CPU
  * memory

Expected output:

```text
표준 수집 산출물 1세트 + Pi 리소스 로그
```

Current implementation interpretation:

* Docker container is the Pi gateway
* `/work/target` stores C source, binary, firmware, or config files
* `/work/logs` stores collected logs and reports
* Resource logging may be added after the Docker MVP works

---

### Block 3: 1:30–2:30 — Execute Both Paths & Measure

Original slide content:

* 클라우드 LLM 분석 1회
* Fuzzing 탐지 1회
* 결과 및 지표 로깅

Detailed slide content:

Route A:

* Send collected input to Cloud/Local LLM
* Analyze vulnerability candidates
* Record time

Route B:

* Run Fuzzing such as boofuzz or simple mutation fuzzing
* Send mutated inputs to the same target
* Observe crash or abnormal behavior

Both paths must log:

* result
* time
* resource usage
* false positive candidates

Expected output:

```text
경로별 원시 결과 + 계측 로그
```

Current revised implementation:

```text
Route A: LLM candidate generation
Route B: Fuzzing execution
Route C: Verification for false-positive reduction
```

The verifier must rerun suspicious inputs and decide whether findings are reproducible.

---

### Block 4: 2:30–3:00 — Comparison Table & Cleanup

Original slide content:

* 4개 지표 비교표 1차 작성
* 관찰 및 한계 메모
* Notion / GitHub 기록

Detailed slide content:

* Compare 4 metrics:

  * 탐지율
  * 시간
  * 리소스
  * 오탐
* Write LLM vs Fuzzing strengths and weaknesses
* Record observations and limitations
* Upload results to Notion and GitHub

Expected output:

```text
4 지표 비교표 + 관찰 메모
```

Current revised metrics:

* Detection Rate
* Verification Success Rate
* Total Time
* False Positive Rate

Optional supporting metrics:

* CPU usage
* memory usage
* crash count
* timeout count
* sanitizer error count
* reproducibility count

---

## Evaluation Metrics

Use these primary metrics:

| Metric                    | Meaning                                                     | Calculation                                            |
| ------------------------- | ----------------------------------------------------------- | ------------------------------------------------------ |
| Detection Rate            | How many known vulnerabilities were found as LLM candidates | `LLM candidate matches / ground-truth vulnerabilities` |
| Verification Success Rate | How many LLM candidates were confirmed by execution         | `CONFIRMED / LLM candidates`                           |
| False Positive Rate       | How many LLM candidates were not confirmed                  | `FALSE_POSITIVE / LLM candidates`                      |
| Total Time                | End-to-end analysis time                                    | `LLM time + fuzzing time + verification time`          |

Optional metrics:

| Metric                | Meaning                                        |
| --------------------- | ---------------------------------------------- |
| Crash Count           | Number of abnormal exits during fuzzing        |
| Timeout Count         | Number of timeout cases                        |
| Sanitizer Error Count | Number of sanitizer-detected memory errors     |
| Reproducibility Count | Number of inputs that reproduce the same issue |
| CPU Usage             | CPU usage during fuzzing                       |
| Memory Usage          | Maximum memory usage during analysis           |

---

## Final Classification Status

All findings must use one of these statuses:

```text
LLM_CANDIDATE
```

The LLM suspected a vulnerability, but it has not been tested yet.

```text
FUZZ_TRIGGERED
```

Fuzzing produced a suspicious crash, timeout, sanitizer error, or abnormal behavior.

```text
CONFIRMED
```

The suspicious behavior was reproduced during verification.

```text
NOT_REPRODUCED
```

Fuzzing found suspicious behavior, but it did not reproduce reliably.

```text
FALSE_POSITIVE
```

The LLM suspected a vulnerability, but fuzzing and verification did not confirm it.

Rule:

```text
Only CONFIRMED findings should be treated as final vulnerabilities.
```

---

## Verification Policy

To reduce false positives:

1. Do not trust LLM output alone.
2. Run fuzzing against the target.
3. Save any input that causes crash, timeout, sanitizer error, or abnormal behavior.
4. Rerun suspicious inputs.
5. If the same issue occurs at least 2 times out of 3 reruns, classify as `CONFIRMED`.
6. Otherwise classify as `NOT_REPRODUCED` or `FALSE_POSITIVE`.

---

## Expected Project Structure

Use this structure unless the user changes it:

```text
project/
├── AGENTS.md
├── README.md
├── Dockerfile
├── docker-compose.yml
├── analyzer/
│   ├── __init__.py
│   ├── main.py
│   ├── ollama_client.py
│   ├── prompt_builder.py
│   ├── candidate_parser.py
│   ├── seed_generator.py
│   ├── simple_fuzzer.py
│   ├── verifier.py
│   └── result_writer.py
│
└── work/
    ├── target/
    │   ├── input.c
    │   └── target_binary
    │
    ├── seeds/
    ├── crashes/
    └── logs/
        ├── llm_candidates.json
        ├── fuzz_result.json
        ├── verification_result.json
        └── final_report.md
```

---

## Docker Gateway Requirements

First Docker MVP must implement:

### Dockerfile

* Base image: `python:3.11-slim`
* Install:

  * gcc
  * clang
  * make
  * curl
  * jq
  * file
  * coreutils
* Install Python package:

  * requests
* Run:

  * `python -m analyzer.main`

### docker-compose.yml

Service name:

```text
pi-gateway
```

Container name:

```text
pi-gateway
```

Network:

```yaml
network_mode: "host"
```

Volumes:

```yaml
- ./work:/work
- ./analyzer:/app/analyzer
```

Environment:

```yaml
OLLAMA_BASE_URL: "http://127.0.0.1:11434"
OLLAMA_MODEL: "gemma4"
WORK_DIR: "/work"
```

First success criteria:

```text
docker compose up --build
```

must show:

* container started
* `/work/target` exists
* `/work/seeds` exists
* `/work/crashes` exists
* `/work/logs` exists
* host Ollama API connection successful

---

## Ollama Integration Rules

The LLM client must:

* use `OLLAMA_BASE_URL`
* use `OLLAMA_MODEL`
* call `/api/generate`
* support `stream: false`
* handle connection errors clearly
* save raw LLM output if parsing fails
* never silently ignore LLM errors

Default API endpoint:

```text
http://127.0.0.1:11434/api/generate
```

The model name should default to:

```text
gemma4
```

but must be configurable through environment variables.

---

## LLM Prompt Requirements

The LLM prompt must ask for structured JSON.

The LLM must return candidates in this shape:

```json
{
  "candidates": [
    {
      "candidate_id": "LLM-001",
      "vulnerability_type": "buffer_overflow",
      "file": "input.c",
      "function": "parse_config",
      "reason": "Unsafe copy without length validation",
      "evidence": "strcpy(dst, input)",
      "suggested_seeds": [
        "normal",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "%x%x%x%x"
      ],
      "confidence": "medium",
      "status": "LLM_CANDIDATE"
    }
  ]
}
```

The parser should be tolerant of imperfect LLM output.

If JSON parsing fails:

* save raw output to `/work/logs/llm_raw_output.txt`
* create a fallback candidate or return an empty candidate list
* do not crash the entire pipeline unless necessary

---

## Fuzzing Rules

The first fuzzer should be a simple Python mutation fuzzer.

Do not add AFL++, QEMU, or complex external fuzzers in the first MVP.

Mutation examples:

* repeat strings
* long input
* boundary length input
* format string patterns
* path traversal-like strings for detection only
* null bytes
* random bytes
* mixed ASCII input

The fuzzer should:

* read seed inputs from `/work/seeds`
* run the target binary with mutated input
* enforce timeout
* capture stdout/stderr
* record exit code
* save crash-triggering inputs to `/work/crashes`
* write `/work/logs/fuzz_result.json`

---

## Compilation Rules

For sample C targets, compile with sanitizer options when possible:

```bash
clang -fsanitize=address,undefined -g -O1 -o /work/target/target_binary /work/target/input.c
```

If sanitizer compilation fails, fall back to normal compilation:

```bash
gcc -g -O0 -o /work/target/target_binary /work/target/input.c
```

Compilation errors must be written to logs.

---

## Report Rules

Generate both JSON and Markdown outputs.

Required files:

```text
/work/logs/llm_candidates.json
/work/logs/fuzz_result.json
/work/logs/verification_result.json
/work/logs/final_report.md
```

The Markdown report must include:

* project name
* target file name
* environment summary
* LLM candidate summary
* fuzzing summary
* verification summary
* final classification table
* observations
* limitations
* next steps

---

## Safety and Scope Rules

This project is for defensive security research and controlled educational testing only.

Do not implement features for attacking real third-party systems.

Do not add:

* stealth
* persistence
* credential theft
* unauthorized scanning
* malware behavior
* exploit deployment against real services
* destructive payloads

All fuzzing should run only on local sample programs, authorized firmware, or intentionally vulnerable educational targets.

---

## Current Development Stage

Current stage:

```text
Stage 1 completed: Architecture & evaluation design
Stage 2 current: Docker-based Raspberry Pi gateway implementation
```

Do next:

```text
1. Implement Dockerfile
2. Implement docker-compose.yml
3. Implement analyzer/main.py
4. Create required work directories
5. Test Host Ollama API connection
```

Do not proceed to full LLM-fuzzing-verification pipeline until the Docker gateway successfully runs.

---

## Definition of Done for Current Task

The current Docker gateway task is complete when:

```text
[ ] docker compose up --build works
[ ] pi-gateway container starts
[ ] /work/target exists
[ ] /work/seeds exists
[ ] /work/crashes exists
[ ] /work/logs exists
[ ] Ollama /api/tags request succeeds from inside the container
[ ] clear success/failure logs are printed
```

After this, implement:

```text
LLM candidate generation → seed generation → simple fuzzing → verification → report generation
```
