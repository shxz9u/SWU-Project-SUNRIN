# 연구노트 - 2026-06-27

## 1. 오늘의 목표

Docker 컨테이너를 Raspberry Pi 분석 게이트웨이처럼 사용해 C 기반 IoT 샘플 대상 1개에 대해 LLM 분석 경로와 fuzzing 경로를 각각 실행하고, 탐지율/시간/리소스/오탐 수 기준의 비교표 초안을 만든다.

## 2. 실제로 한 일

- Python 3.11 기반 `pi-gateway` Docker 실행 환경을 구성했다.
- 원격 Ollama API(`http://210.110.103.200:11434`)와 컨테이너 연결을 확인했다.
- IoT 설정 파서 형태의 C 타겟(`work/target/input.c`)과 정답셋(`work/target/ground_truth.json`)을 준비했다.
- LLM 후보 분석, seed 생성, mutation fuzzing, 재현성 검증 경로를 실행했다.
- boofuzz 기반 독립 fuzzing 경로를 추가하고 실행했다.
- 경로별 원시 결과, 시간, CPU, RSS 로그를 저장했다.
- `docs/627_1.md` 요구사항과 현재 구현 상태를 대조했다.
- README에 실행 방법과 산출물 위치를 정리했다.

## 3. 나온 결과

- `docker compose up --build` 실행 성공.
- Ollama `/api/tags` 연결 성공.
- LLM Fuzzer 경로: 탐지율 `83.33%`, 검증 탐지율 `50.00%`, 소요 시간 `43.377268s`, 오탐 수 `2`.
- boofuzz 경로: 탐지율 `66.67%`, 검증 탐지율 `66.67%`, 소요 시간 `0.600668s`, 오탐 수 `0`.
- LLM seed mutation fuzzing: 총 `200`회 실행, suspicious input `26`개, sanitizer error `27`회, 검증 `26/26`개 재현.
- boofuzz: 총 `84`개 case 실행, suspicious input `20`개, sanitizer error `20`회, 검증 `20/20`개 재현.
- 결과 비교 로그 1개: `work/logs/comparison_report.md`

## 4. 막힌 점

- 처음에는 로컬 Ollama 설치와 네트워크 상태가 불안정해서 원격 Ollama API를 사용하도록 전환했다.
- boofuzz는 일반적인 네트워크 서비스 fuzzing 흐름이지만, 현재 타겟은 stdin 기반 로컬 바이너리라 case generator 방식으로 맞춰 적용했다.
- 리소스 측정은 Docker 전체 cgroup 기준이 아니라 Python `resource.getrusage` 기준이라 컨테이너 전체 리소스 로그로 보기에는 한계가 있다.
- 현재 대상은 실제 펌웨어가 아니라 교육용 C 샘플이므로 결과를 실제 IoT 펌웨어 성능으로 일반화할 수 없다.

## 5. 배운 점

- LLM 후보는 취약점 최종 판정이 아니라 fuzzing seed와 의심 지점 생성에 더 적합하다.
- 실행 기반 증거와 재현성 검증을 붙이면 LLM 오탐을 비교 가능한 수치로 정리할 수 있다.
- 같은 C 타겟이라도 LLM seed mutation 경로와 boofuzz 경로의 탐지 범위와 시간 특성이 다르게 나온다.
- 연구 기록에는 원시 결과 JSON, 비교 Markdown, 정답셋이 같이 있어야 나중에 실험 재현이 가능하다.

## 6. 다음 목표

현재 샘플 C 타겟을 유지한 상태에서 Docker cgroup 기반 리소스 수집을 추가하고, boofuzz/LLM 경로의 비교 기준을 더 엄밀하게 정리한다.

## 다음 세션 목표 1줄

Docker cgroup 리소스 로그를 붙여 LLM Fuzzer와 boofuzz 비교표의 리소스 지표를 보강한다.
