# 서울여자대학교 AI정보보호영재교육원 전문R&E 프로젝트 - SUNRIN팀

# 주제
라즈베리파이-클라우드 연계형 IoT 취약점 분석 시스템 연구: LLM 기반 분석과 Fuzzing 기법의 비교

본 프로젝트는 제한된 성능을 가진 IoT 환경에서 라즈베리파이를 보안 분석 게이트웨이로 활용하여, IoT 장치 또는 IoT 서비스를 대상으로 자동화된 취약점 탐지를 수행하는 시스템을 구현하는 것을 목표로 한다.

라즈베리파이는 대상 IoT 장치와 네트워크로 연결되어 입력 벡터를 수집하고, 사용자는 분석 모드를 선택하여 Fuzzing 기반 탐지 또는 LLM 기반 분석을 수행할 수 있다. 이후 탐지 결과를 비교하여 각 방식의 장점과 한계를 분석한다.

# 연구 배경
IoT 장치는 웹 서버, API, MQTT, HTTP 기반 제어 인터페이스 등 다양한 입력 지점을 가진다. 그러나 많은 IoT 장치는 제한된 하드웨어 성능과 낮은 보안 수준으로 인해 취약점에 노출되기 쉽다.

기존 취약점 탐지 방식 중 Fuzzing은 실제 입력을 반복적으로 전송하여 비정상 동작을 탐지하는 데 강점이 있다. 반면 LLM 기반 분석은 코드, API 구조, 요청 형식 등을 해석하여 의미 있는 테스트 입력을 생성하는 데 활용될 수 있다.

본 연구는 두 방식을 동일한 IoT 환경에서 적용하고, 탐지 성능과 효율성을 비교하여 IoT 보안 분석에 적합한 접근 방식을 탐구한다.

# LLM Fuzzer 기본 사용법

호스트 PC에서 Ollama Gemma4가 `11434` 포트로 실행 중일 때, 스캔 결과 JSON을 기반으로 fuzzing 테스트 케이스를 생성할 수 있다.

```bash
python3 -m llm_fuzzer.cli \
  --input examples/sample_scan.json \
  --output results/fuzzing_results/sample_plan.json \
  --ollama-url http://127.0.0.1:11434 \
  --model gemma4
```

기본 실행은 테스트 케이스 생성까지만 수행한다. 허가된 테스트 대상에 HTTP fuzzing을 실제 전송하려면 명시적으로 실행 옵션을 추가한다.

```bash
python3 -m llm_fuzzer.cli \
  --input examples/sample_scan.json \
  --output results/fuzzing_results/sample_run.json \
  --ollama-url http://127.0.0.1:11434 \
  --model gemma4 \
  --execute-http \
  --target-base-url http://192.168.0.25 \
  --i-have-authorization
```

출력 JSON은 `llm_plan`과 `execution_results`를 분리하여 저장하므로, 이후 LLM 기반 분석 결과와 실제 fuzzing 결과를 비교하는 파이프라인에 사용할 수 있다.

# Contributor
<br>
PM : [유승주](https://github.com/shxz9u)<br>
develop : [김주한](https://github.com/kjuhan1020)<br>
analyze : [이지한](https://github.com/34syH)<br>
analyze : 박현우
