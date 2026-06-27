# Raspberry Pi IoT Analysis Gateway

Linux Host PC에서 Docker 컨테이너를 Raspberry Pi 분석 게이트웨이처럼 실행해 IoT/C 코드 취약점 분석 흐름을 검증하는 프로젝트입니다.

현재 구현 범위는 실제 펌웨어 분석이 아니라, 가벼운 C 기반 IoT 설정 파서 1개를 대상으로 다음 1회전을 끝내는 것입니다.

```text
LLM 후보 분석 -> LLM seed 기반 mutation fuzzing -> boofuzz 경로 fuzzing -> 재현성 검증 -> 경로별 비교
```

LLM 결과는 최종 취약점으로 보지 않습니다. 최종 판정은 crash, sanitizer error, timeout, abnormal exit 같은 실행 증거와 3회 재실행 중 2회 이상 재현 여부를 기준으로 합니다.

## 구성

```text
Dockerfile
docker-compose.yml
analyzer/
  main.py
  ollama_client.py
  prompt_builder.py
  candidate_parser.py
  seed_generator.py
  simple_fuzzer.py
  boofuzz_fuzzer.py
  verifier.py
  resource_monitor.py
  comparison_writer.py
  result_writer.py
work/
  target/
    input.c
    ground_truth.json
  seeds/
  crashes/
  logs/
```

분석 대상은 [work/target/input.c](/home/magnolia/SWU-Project-SUNRIN/work/target/input.c) 입니다. `ssid`, `password`, `topic`, `log`, `auth`, `port`, `cmd` 설정 라인을 stdin으로 받아 처리하는 IoT 게이트웨이 설정 파서 형태입니다.

정답셋은 [work/target/ground_truth.json](/home/magnolia/SWU-Project-SUNRIN/work/target/ground_truth.json)에 있으며 현재 6개 항목입니다.

## 빠른 실행

현재 기본 Ollama API는 원격 서버로 설정되어 있습니다.

```text
http://210.110.103.200:11434
```

전체 파이프라인 실행:

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose up --build --remove-orphans --abort-on-container-exit --exit-code-from pi-gateway
```

성공하면 `pi-gateway` 컨테이너가 다음 작업을 수행합니다.

```text
1. /work/target, /work/seeds, /work/crashes, /work/logs, /work/build 생성
2. Ollama /api/tags 연결 확인
3. input.c를 AddressSanitizer/UBSan 옵션으로 컴파일
4. Ollama Gemma4에 취약점 후보 분석 요청
5. LLM suggested seed와 baseline seed 생성
6. LLM seed 기반 mutation fuzzer 실행
7. boofuzz 기반 독립 fuzzing 경로 실행
8. 의심 입력 3회 재실행 검증
9. JSON/Markdown 보고서 생성
```

## 환경 변수

주요 설정은 [docker-compose.yml](/home/magnolia/SWU-Project-SUNRIN/docker-compose.yml)에 있습니다.

| 변수 | 기본값 | 의미 |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://210.110.103.200:11434` | Ollama API 주소 |
| `OLLAMA_MODEL` | `gemma4` | 분석에 사용할 모델명 |
| `WORK_DIR` | `/work` | 컨테이너 내부 작업 디렉터리 |
| `FUZZ_ITERATIONS` | `200` | LLM seed mutation fuzzer 실행 횟수 |
| `FUZZ_TIMEOUT_SECONDS` | `2` | 대상 바이너리 1회 실행 제한 시간 |
| `FUZZ_INPUT_MODE` | `stdin` | 대상 바이너리에 입력을 전달하는 방식 |
| `FUZZ_RANDOM_SEED` | `1337` | mutation 재현용 난수 seed |
| `FUZZ_VERIFY_RUNS` | `3` | 의심 입력 재실행 횟수 |
| `FUZZ_VERIFY_THRESHOLD` | `2` | CONFIRMED 판정 최소 재현 횟수 |
| `BOOFUZZ_MAX_CASES` | `200` | boofuzz 경로 최대 case 수 |

일시적으로 로컬 Ollama를 쓰려면 실행 시 override할 수 있습니다.

```bash
OLLAMA_BASE_URL=http://127.0.0.1:11434 DOCKER_CONFIG=/tmp/docker-config docker compose up --build --abort-on-container-exit --exit-code-from pi-gateway
```

## 산출물

주요 결과는 `work/logs`에 저장됩니다.

| 파일 | 내용 |
| --- | --- |
| `llm_candidates.json` | Ollama가 생성한 취약점 후보 원시 결과 |
| `llm_raw_output.txt` | LLM JSON 파싱 실패 시 원문 보관 |
| `seed_generation.json` | LLM seed와 baseline seed 생성 목록 |
| `fuzz_result.json` | LLM seed 기반 mutation fuzzing 원시 결과 |
| `verification_result.json` | LLM fuzzer 의심 입력 재현성 검증 결과 |
| `llm_fuzzer_result.json` | LLM 후보 분석, seed 생성, mutation fuzzing, 검증을 묶은 경로별 원시 결과 |
| `llm_fuzzer_verification_result.json` | LLM fuzzer 경로 검증 결과 사본 |
| `boofuzz_result.json` | boofuzz 경로 원시 결과 |
| `boofuzz_verification_result.json` | boofuzz 경로 재현성 검증 결과 |
| `resource_usage.json` | 경로별 wall time, CPU time, 평균 CPU%, max RSS |
| `comparison_result.json` | 두 경로의 탐지율, 시간, 리소스, 오탐 수 비교 JSON |
| `comparison_report.md` | 두 경로 비교표 Markdown |
| `627_1_alignment.md` | `docs/627_1.md` 요구사항 대비 구현 상태 점검표 |
| `final_report.md` | LLM fuzzer 경로 중심 최종 요약 보고서 |

의심 입력은 경로별로 나뉘어 저장됩니다.

```text
work/crashes/llm_fuzzer/
work/crashes/boofuzz/
```

## 오늘 비교 기준

[docs/627_1.md](/home/magnolia/SWU-Project-SUNRIN/docs/627_1.md)의 오늘 목표는 “수집 -> 분석 -> 비교 1회전 완성”입니다. 현재 비교표는 다음 4개 기준을 사용합니다.

| 기준 | 현재 계산 방식 |
| --- | --- |
| 탐지율 | 탐지된 ground-truth id 수 / 전체 ground-truth id 수 |
| 걸린 시간 | 경로별 wall-clock seconds |
| 사용 리소스 | Python `resource.getrusage` 기반 CPU seconds, 평균 CPU%, max RSS |
| 오탐 수 | LLM 경로는 미검증 후보 수, boofuzz 경로는 재현되지 않은 suspicious finding 수 |

최근 실행 결과는 [work/logs/comparison_report.md](/home/magnolia/SWU-Project-SUNRIN/work/logs/comparison_report.md)에 있습니다.

## 부분 실행

Docker 이미지만 빌드:

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose build pi-gateway
```

기존 대상 바이너리로 simple fuzzer만 실행:

```bash
DOCKER_CONFIG=/tmp/docker-config ./scripts/run_fuzzer.sh --iterations 100
```

컨테이너 안에서 boofuzz case 생성만 확인:

```bash
DOCKER_CONFIG=/tmp/docker-config docker compose run --rm --no-deps pi-gateway python - <<'PY'
from analyzer.boofuzz_fuzzer import generate_boofuzz_cases
for case in generate_boofuzz_cases(5):
    print(case["case_id"], case["field"], case["payload"])
PY
```

## 로컬 Ollama 사용

나중에 Host PC에서 직접 Ollama를 띄울 경우:

```bash
OLLAMA_BASE_URL=http://127.0.0.1:11434 OLLAMA_MODEL=gemma4 ./scripts/setup_ollama.sh
```

이 스크립트는 `docker compose --profile local-ollama up -d ollama`로 로컬 Ollama 컨테이너를 띄우고 모델을 pull합니다. 이후 `docker-compose.yml`의 `OLLAMA_BASE_URL`을 `http://127.0.0.1:11434`로 바꾸거나 실행 시 환경 변수로 override하면 됩니다.

## 현재 한계

- 대상은 실제 펌웨어가 아니라 교육용 C 샘플입니다.
- boofuzz는 네트워크 서비스가 아니라 로컬 stdin 기반 바이너리에 맞춰 case generator로 사용합니다.
- 리소스 측정은 Docker cgroup 전체 사용량이 아니라 파이썬 프로세스 기준 `resource.getrusage` 값입니다.
- 탐지율은 `ground_truth.json`과 후보/입력 metadata를 매칭해 계산하므로, 실제 펌웨어 단계에서는 정답셋과 매칭 규칙을 다시 정교화해야 합니다.

## 안전 범위

이 프로젝트는 허가된 로컬 샘플, 교육용 취약 타겟, 또는 팀이 소유한 펌웨어만 대상으로 합니다. 실제 제3자 시스템 공격, 인증정보 탈취, 지속성, 은닉, 파괴형 payload, 무단 스캔 기능은 구현하지 않습니다.
