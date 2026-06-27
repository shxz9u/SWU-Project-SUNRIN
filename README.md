# Raspberry Pi IoT Analysis Gateway

Docker 컨테이너를 Raspberry Pi 분석 게이트웨이처럼 사용해 IoT/Firmware 계열 C 코드 취약점 분석 파이프라인을 검증하는 프로젝트입니다.

현재 목표는 실제 Raspberry Pi나 실제 펌웨어 없이도 다음 흐름을 한 번 끝까지 실행하는 것입니다.

```text
C 타겟 수집 -> Ollama LLM 후보 분석 -> seed 생성 -> LLM seed mutation fuzzing
              -> boofuzz 경로 fuzzing -> 재현성 검증 -> 경로별 비교 보고서
```

중요한 원칙은 하나입니다. LLM 출력은 최종 취약점 판정이 아니라 후보입니다. 최종 판정은 crash, timeout, sanitizer error, abnormal exit 같은 실행 증거와 재현성 검증 결과를 기준으로 합니다.

## 필요한 것

Host PC에 필요한 것은 다음 정도입니다.

| 항목 | 필요 여부 | 설명 |
| --- | --- | --- |
| Linux Host | 필수 | 현재 Docker `network_mode: host` 기준으로 Linux 환경을 사용합니다. |
| Docker Engine | 필수 | `pi-gateway` 컨테이너 빌드/실행에 필요합니다. |
| Docker Compose v2 | 필수 | `docker compose ...` 명령을 사용합니다. |
| Ollama API | 필수 | 기본값은 원격 `http://210.110.103.200:11434` 입니다. |
| Ollama model | 필수 | 기본 모델명은 `gemma4` 입니다. |
| Host Python | 불필요 | Python/패키지는 Docker 이미지 안에 설치됩니다. |
| gcc/clang/make | Host에는 불필요 | Docker 이미지 안에 설치됩니다. |

Docker 이미지 내부에는 다음 도구가 설치됩니다.

```text
Python 3.11
gcc
clang
make
curl
jq
file
coreutils
requests
boofuzz
```

현재 기본 Ollama 주소는 원격 서버입니다.

```text
http://210.110.103.200:11434
```

로컬 Ollama를 사용할 경우에는 나중에 `OLLAMA_BASE_URL=http://127.0.0.1:11434`로 바꿔 실행하면 됩니다.

## 파일 구조

현재 프로젝트 구조는 다음과 같습니다.

```text
.
├── AGENTS.md
├── Dockerfile
├── README.md
├── docker-compose.yml
├── analyzer/
│   ├── __init__.py
│   ├── main.py
│   ├── ollama_client.py
│   ├── prompt_builder.py
│   ├── candidate_parser.py
│   ├── seed_generator.py
│   ├── simple_fuzzer.py
│   ├── boofuzz_fuzzer.py
│   ├── verifier.py
│   ├── resource_monitor.py
│   ├── comparison_writer.py
│   ├── result_writer.py
│   └── execution.py
├── docs/
│   ├── 627_1.md
│   └── research_note_2026-06-27.md
├── scripts/
│   ├── run_fuzzer.sh
│   └── setup_ollama.sh
└── work/
    ├── target/
    │   ├── input.c
    │   ├── ground_truth.json
    │   └── target_binary
    ├── seeds/
    ├── crashes/
    │   ├── llm_fuzzer/
    │   └── boofuzz/
    ├── logs/
    └── build/
```

각 디렉터리 역할은 다음과 같습니다.

| 경로 | 역할 |
| --- | --- |
| `analyzer/` | Docker 컨테이너 안에서 실행되는 분석 파이프라인 코드 |
| `docs/627_1.md` | 오늘 목표와 평가 설계 문서 |
| `docs/research_note_2026-06-27.md` | 오늘 연구노트 |
| `scripts/setup_ollama.sh` | 로컬 Ollama 컨테이너 설치/모델 pull 보조 스크립트 |
| `scripts/run_fuzzer.sh` | simple fuzzer 단독 실행 보조 스크립트 |
| `work/target/` | 분석 대상 C 코드, 정답셋, 컴파일된 바이너리 |
| `work/seeds/` | LLM seed와 baseline seed |
| `work/crashes/` | crash/sanitizer/timeout 유발 입력 |
| `work/logs/` | JSON/Markdown 결과 로그 |
| `work/build/` | 빌드 보조 디렉터리 |

## 현재 분석 대상

현재 타겟은 `work/target/input.c`입니다.

이 파일은 IoT 게이트웨이 설정 파서처럼 stdin에서 설정 라인을 읽습니다.

입력 예시는 다음과 같습니다.

```text
ssid=iot-lab
password=guest1234
topic=telemetry/data
log=boot ok
port=1883
auth=admin:sunrin_admin123
cmd=status
```

정답셋은 `work/target/ground_truth.json`입니다. 현재 포함된 취약점 유형은 다음과 같습니다.

```text
GT-001 ssid strcpy 기반 buffer overflow
GT-002 password strcpy 기반 buffer overflow
GT-003 topic strcat 기반 buffer overflow
GT-004 printf(value) 기반 format string
GT-005 hardcoded credentials
GT-006 port atoi 기반 missing input validation
```

새 타겟으로 바꾸려면 기본적으로 두 파일을 수정하면 됩니다.

```text
work/target/input.c
work/target/ground_truth.json
```

`FUZZ_RECOMPILE=1`이 기본값이라 `docker compose up --build`를 다시 실행하면 `input.c`가 다시 컴파일됩니다.

## 한 번에 실행

이 프로젝트에서 가장 중요한 실행 명령은 다음입니다.

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose up --build --remove-orphans --abort-on-container-exit --exit-code-from pi-gateway
```

`DOCKER_CONFIG=/tmp/docker-config`는 현재 개발 환경에서 Docker credential/config 권한 문제를 피하기 위한 설정입니다. 본인 환경에서 Docker가 정상 동작하면 생략해도 됩니다.

실행이 성공하면 로그에 대략 다음 흐름이 보입니다.

```text
Raspberry Pi analysis gateway container starting
checking Ollama API: .../api/tags
Ollama connection succeeded
work directory ready: /work/target
compiling target with sanitizer command: clang ...
running LLM fuzzer route
LLM candidate count: ...
seed generation complete: ...
starting mutation fuzzing
running boofuzz route
comparison written: /work/logs/comparison_report.md
pipeline completed
```

컨테이너는 장기 실행 서비스가 아니라 분석 1회전을 마치면 종료됩니다. 종료 코드가 `0`이면 성공입니다.

## 실행 전에 확인할 것

Ollama API가 열려 있는지 Host에서 먼저 확인할 수 있습니다.

```bash
curl -fsS http://210.110.103.200:11434/api/tags | jq .
```

모델 목록에 `gemma4` 또는 `gemma4:latest`가 있으면 기본 설정으로 실행할 수 있습니다.

Docker Compose 설정이 유효한지 확인하려면 다음을 실행합니다.

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose config
```

이미지만 먼저 빌드하려면 다음을 실행합니다.

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose build pi-gateway
```

## 환경 변수

`docker-compose.yml`은 환경변수 override를 지원합니다.

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://210.110.103.200:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `gemma4` | LLM 분석 모델명 |
| `OLLAMA_CONNECT_RETRIES` | `30` | Ollama 연결 재시도 횟수 |
| `OLLAMA_CONNECT_DELAY_SECONDS` | `2` | 연결 재시도 간격 |
| `OLLAMA_REQUEST_TIMEOUT_SECONDS` | `120` | LLM generate 요청 timeout |
| `WORK_DIR` | `/work` | 컨테이너 내부 작업 디렉터리 |
| `FUZZ_RECOMPILE` | `1` | `1`이면 실행 때마다 C 타겟 재컴파일 |
| `FUZZ_ITERATIONS` | `200` | LLM seed mutation fuzzer 반복 횟수 |
| `FUZZ_TIMEOUT_SECONDS` | `2` | 타겟 바이너리 1회 실행 timeout |
| `FUZZ_INPUT_MODE` | `stdin` | 현재는 stdin 입력 방식 사용 |
| `FUZZ_RANDOM_SEED` | `1337` | mutation fuzzer 난수 seed |
| `FUZZ_VERIFY_RUNS` | `3` | suspicious input 재실행 횟수 |
| `FUZZ_VERIFY_THRESHOLD` | `2` | `CONFIRMED` 판정 최소 재현 횟수 |
| `BOOFUZZ_MAX_CASES` | `200` | boofuzz 경로 최대 case 수 |

예를 들어 fuzzing 횟수를 줄여 빠르게 테스트하려면 다음처럼 실행합니다.

```bash
FUZZ_ITERATIONS=50 BOOFUZZ_MAX_CASES=50 DOCKER_CONFIG=/tmp/docker-config docker compose up --build --abort-on-container-exit --exit-code-from pi-gateway
```

로컬 Ollama를 쓰려면 다음처럼 실행합니다.

```bash
OLLAMA_BASE_URL=http://127.0.0.1:11434 OLLAMA_MODEL=gemma4 DOCKER_CONFIG=/tmp/docker-config docker compose up --build --abort-on-container-exit --exit-code-from pi-gateway
```

## 로컬 Ollama 세팅

원격 Ollama 대신 Host PC에서 Ollama를 컨테이너로 띄우려면 다음 스크립트를 사용합니다.

```bash
OLLAMA_BASE_URL=http://127.0.0.1:11434 OLLAMA_MODEL=gemma4 ./scripts/setup_ollama.sh
```

이 스크립트가 하는 일은 다음과 같습니다.

```text
1. docker compose --profile local-ollama up -d ollama 실행
2. http://127.0.0.1:11434/api/tags 준비 상태 확인
3. docker exec ollama ollama pull gemma4 실행
4. 설치된 모델 목록 출력
```

로컬 Ollama 세팅 후 분석을 실행하려면 다음처럼 `OLLAMA_BASE_URL`을 로컬로 지정합니다.

```bash
OLLAMA_BASE_URL=http://127.0.0.1:11434 DOCKER_CONFIG=/tmp/docker-config docker compose up --build --abort-on-container-exit --exit-code-from pi-gateway
```

## 파이프라인 동작 방식

`python -m analyzer.main`이 전체 파이프라인을 실행합니다.

```text
1. work 디렉터리 생성
2. Ollama /api/tags 연결 확인
3. work/target/input.c 컴파일
4. Ollama /api/generate 호출
5. LLM JSON 후보 파싱
6. LLM suggested seed와 baseline seed 생성
7. LLM seed mutation fuzzer 실행
8. suspicious input 저장
9. suspicious input 3회 재실행 검증
10. boofuzz case 생성
11. boofuzz 경로 실행
12. boofuzz suspicious input 검증
13. 경로별 시간/CPU/RSS 측정
14. JSON과 Markdown 보고서 저장
```

## 두 fuzzing 경로

현재 비교하는 경로는 두 개입니다.

| 경로 | 설명 | 원시 결과 |
| --- | --- | --- |
| LLM Fuzzer | LLM이 찾은 후보와 suggested seed를 기반으로 seed 파일을 만들고 mutation fuzzing 수행 | `work/logs/llm_fuzzer_result.json` |
| boofuzz | boofuzz primitive를 사용해 설정 라인 입력 case를 만들고 동일 바이너리에 실행 | `work/logs/boofuzz_result.json` |

boofuzz는 원래 네트워크 프로토콜 fuzzing에 많이 쓰이지만, 현재 단계에서는 네트워크 서비스가 없으므로 stdin 기반 C 바이너리에 입력 case를 생성하는 방식으로 적용했습니다.

## 결과 파일

실행 결과는 `work/logs/`에 저장됩니다.

| 파일 | 봐야 하는 시점 | 내용 |
| --- | --- | --- |
| `compile.log` | 컴파일 실패 시 | clang/gcc 컴파일 로그 |
| `llm_candidates.json` | LLM 분석 확인 | LLM 후보, suggested seed, 모델 응답 정보 |
| `llm_raw_output.txt` | LLM JSON 파싱 실패 시 | 파싱 실패한 원본 LLM 응답 |
| `seed_generation.json` | seed 확인 | 생성된 seed 파일 목록 |
| `fuzz_result.json` | LLM fuzzer 원시 확인 | mutation fuzzing 실행별 결과 |
| `verification_result.json` | LLM fuzzer 검증 확인 | suspicious input 재현성 검증 결과 |
| `llm_fuzzer_result.json` | LLM 경로 전체 확인 | LLM 분석, seed, fuzzing, 검증 묶음 |
| `llm_fuzzer_verification_result.json` | LLM 경로 검증만 확인 | LLM fuzzer 검증 결과 사본 |
| `boofuzz_result.json` | boofuzz 원시 확인 | boofuzz case별 실행 결과 |
| `boofuzz_verification_result.json` | boofuzz 검증 확인 | boofuzz suspicious input 재현성 검증 |
| `resource_usage.json` | 리소스 확인 | 경로별 wall time, CPU seconds, 평균 CPU%, max RSS |
| `comparison_result.json` | 비교 데이터 확인 | 두 경로 비교 JSON |
| `comparison_report.md` | 보고서 작성용 | 탐지율/시간/리소스/오탐 수 비교표 |
| `627_1_alignment.md` | 목표 정합성 확인 | `docs/627_1.md` 대비 구현 상태 |
| `final_report.md` | 요약 확인 | LLM fuzzer 중심 최종 보고서 |

가장 먼저 볼 파일은 다음 두 개입니다.

```text
work/logs/comparison_report.md
work/logs/627_1_alignment.md
```

터미널에서 바로 확인하려면 다음 명령을 씁니다.

```bash
sed -n '1,160p' work/logs/comparison_report.md
sed -n '1,180p' work/logs/627_1_alignment.md
```

JSON으로 수치만 확인하려면 다음을 씁니다.

```bash
jq '.routes' work/logs/comparison_result.json
jq '.routes' work/logs/resource_usage.json
```

## 현재 실행 결과 예시

마지막 실행 기준 주요 결과는 다음과 같습니다.

| Route | Detection Rate | Confirmed Detection Rate | Time | CPU | Avg CPU | Max RSS | False Positives |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| LLM Fuzzer | 83.33% | 50.00% | 43.377268s | 0.836672s | 1.93% | 107452 KB | 2 |
| boofuzz | 66.67% | 66.67% | 0.600668s | 0.613296s | 102.10% | 107452 KB | 0 |

해석은 다음과 같습니다.

```text
LLM Fuzzer는 더 많은 정답셋 후보를 짚었지만, 실행 검증 기준으로는 일부만 CONFIRMED 됨.
boofuzz는 LLM 호출 시간이 없어서 훨씬 빠르고, 현재 case에서는 오탐 없이 재현된 sanitizer error를 냄.
```

## 의심 입력 확인

실제 sanitizer error를 유발한 입력은 다음 위치에 저장됩니다.

```text
work/crashes/llm_fuzzer/
work/crashes/boofuzz/
```

파일명은 예를 들어 다음과 같습니다.

```text
FUZZ-001_sanitizer_error.input
BOOFUZZ-001_sanitizer_error.input
```

내용을 확인하려면 다음을 실행합니다.

```bash
sed -n '1,40p' work/crashes/llm_fuzzer/FUZZ-001_sanitizer_error.input
sed -n '1,40p' work/crashes/boofuzz/BOOFUZZ-001_sanitizer_error.input
```

바이너리에 직접 넣어 재현하려면 다음을 실행합니다.

```bash
work/target/target_binary < work/crashes/llm_fuzzer/FUZZ-001_sanitizer_error.input
```

## 단독 실행 명령

simple fuzzer만 따로 실행하려면 다음을 사용합니다.

```bash
DOCKER_CONFIG=/tmp/docker-config ./scripts/run_fuzzer.sh --iterations 100
```

boofuzz case 생성만 확인하려면 다음을 사용합니다.

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose run --rm --no-deps pi-gateway python - <<'PY'
from analyzer.boofuzz_fuzzer import generate_boofuzz_cases

for case in generate_boofuzz_cases(5):
    print(case["case_id"], case["field"], case["payload"])
PY
```

컨테이너 안에서 Ollama 연결만 확인하려면 다음을 사용합니다.

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose run --rm --no-deps pi-gateway python - <<'PY'
import os
import requests

base_url = os.environ["OLLAMA_BASE_URL"].rstrip("/")
response = requests.get(f"{base_url}/api/tags", timeout=10)
print(response.status_code)
print(response.text[:500])
PY
```

## 새 C 타겟으로 바꾸는 방법

새로운 C 파일을 분석하려면 다음 순서로 진행합니다.

1. `work/target/input.c`를 새 C 코드로 교체합니다.
2. `work/target/ground_truth.json`에 알고 있는 취약점 정답셋을 적습니다.
3. stdin 입력 방식이 맞는지 확인합니다.
4. 필요하면 `analyzer/boofuzz_fuzzer.py`의 `FIELD_SPECS`를 새 입력 포맷에 맞게 수정합니다.
5. 다시 실행합니다.

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose up --build --abort-on-container-exit --exit-code-from pi-gateway
```

현재 fuzzer는 대상 바이너리에 stdin으로 입력을 넣습니다. 네트워크 서버나 파일 입력 기반 타겟을 쓰려면 `analyzer/execution.py`, `analyzer/simple_fuzzer.py`, `analyzer/boofuzz_fuzzer.py` 쪽의 실행 방식을 맞춰야 합니다.

## 평가 지표

현재 비교표는 `docs/627_1.md`의 오늘 목표에 맞춰 다음 4개 지표를 사용합니다.

| 지표 | 계산 방식 |
| --- | --- |
| 탐지율 | 탐지된 ground-truth id 수 / 전체 ground-truth id 수 |
| 걸린 시간 | 경로별 wall-clock seconds |
| 사용 리소스 | Python `resource.getrusage` 기반 CPU seconds, 평균 CPU%, max RSS |
| 오탐 수 | LLM 경로는 미검증 후보 수, boofuzz 경로는 재현되지 않은 suspicious finding 수 |

상태값은 다음 기준을 따릅니다.

| 상태 | 의미 |
| --- | --- |
| `LLM_CANDIDATE` | LLM이 의심한 후보 |
| `FUZZ_TRIGGERED` | fuzzing 중 이상 동작을 유발한 입력 |
| `CONFIRMED` | 재실행에서 같은 문제가 반복 재현됨 |
| `NOT_REPRODUCED` | 재실행에서 문제가 충분히 반복되지 않음 |
| `FALSE_POSITIVE` | 후보였지만 실행 검증으로 확인되지 않음 |

## 문제 해결

Ollama 연결 실패:

```bash
curl -v http://210.110.103.200:11434/api/tags
```

원격 서버가 안 되면 로컬 Ollama를 띄우거나 `OLLAMA_BASE_URL`을 다른 서버로 바꿔야 합니다.

Docker 권한 문제:

```bash
docker ps
```

권한 에러가 나면 현재 사용자가 Docker 그룹에 없거나 Docker daemon이 실행 중이 아닐 수 있습니다.

모델이 없다는 경고:

```text
configured Ollama model not listed by /api/tags
```

이 경우 `OLLAMA_MODEL`을 `/api/tags`에 실제로 보이는 모델명으로 바꾸거나 해당 모델을 pull해야 합니다.

컴파일 실패:

```bash
sed -n '1,200p' work/logs/compile.log
```

`input.c` 문법 문제이거나 sanitizer 옵션과 충돌한 경우입니다. sanitizer 컴파일이 실패하면 코드가 fallback 컴파일을 시도합니다.

LLM JSON 파싱 실패:

```bash
sed -n '1,200p' work/logs/llm_raw_output.txt
```

LLM이 JSON 외 텍스트를 많이 섞었을 수 있습니다. 이 경우 prompt나 parser를 조정해야 합니다.

## 현재 한계

- 현재 타겟은 실제 펌웨어가 아니라 교육용 C 샘플입니다.
- boofuzz는 네트워크 서비스가 아니라 stdin 기반 로컬 바이너리 case generator로 사용 중입니다.
- 리소스 측정은 Docker cgroup 전체 사용량이 아니라 Python 프로세스 기준 `resource.getrusage` 값입니다.
- 탐지율은 `ground_truth.json`과 후보/입력 metadata를 매칭해 계산합니다.
- 실제 펌웨어 단계로 가면 입력 방식, 정답셋, boofuzz field 정의, 리소스 측정 방식을 다시 맞춰야 합니다.

## 관련 문서

| 파일 | 내용 |
| --- | --- |
| `AGENTS.md` | 프로젝트 방향, 구현 우선순위, 정책 |
| `docs/627_1.md` | 오늘 목표와 평가 설계 |
| `docs/research_note_2026-06-27.md` | 오늘 연구노트 |
| `work/logs/comparison_report.md` | 최근 실행 비교표 |
| `work/logs/627_1_alignment.md` | `627_1.md` 대비 구현 상태 |

## 안전 범위

이 프로젝트는 허가된 로컬 샘플, 교육용 취약 타겟, 또는 팀이 소유한 펌웨어만 대상으로 합니다.

다음 기능은 구현하지 않습니다.

```text
실제 제3자 시스템 공격
무단 스캔
인증정보 탈취
은닉
지속성
파괴형 payload
악성코드 배포
```
