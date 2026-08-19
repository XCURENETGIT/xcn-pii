# xcn-pii-full Commands

이 문서는 `xcn-pii-full` 프로젝트에서 자주 사용하는 실행, 종료, 점검, API 호출, 벤치마크 명령을 정리한다.

처음 사용하는 운영자/연동 개발자는 `docs/USER_TRAINING_GUIDE.md`를 먼저 읽으면 전체 흐름을 빠르게 따라 할 수 있다.
소스 변경 후 CPU/GPU 이미지를 빠르게 다시 만드는 절차는
[`FAST_SOURCE_RELEASE_BUILD.md`](FAST_SOURCE_RELEASE_BUILD.md)를 참고한다.

모든 명령은 프로젝트 루트에서 실행한다.

```bash
cd /data01/xcn-pii-full
```

Windows 로컬 작업 경로 기준:

```powershell
cd C:\xcn_prj\xcn-pii-full
```

## Environment

기본 환경 파일 생성:

```bash
cp .env.example .env
```

주요 환경 변수:

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `PII_IMAGE_REPO` | `xcn-pii` | Docker 이미지 repository |
| `PII_IMAGE_TAG` | `1.0.9` | Docker 이미지 tag |
| `PII_HTTPS_PORT` | `28443` | HTTPS proxy 외부 포트 |
| `PII_HTTPS_SERVER_NAME` | `_` | TLS server_name |
| `PII_RULESET` | `default` | 기본 룰셋 |
| `PII_GRPC_MAX_WORKERS` | `7` | gRPC handler thread 수 |
| `PII_DETECT_PROCESS_WORKERS` | `4` | 인스턴스별 실제 탐지 process 수 |
| `PII_DETECT_QUEUE_LIMIT` | `1` | 인스턴스별 탐지 대기 한도 (`1` 또는 `2`) |
| `PII_HS_COMBINED_ENABLED` | `true` | Hyperscan combined DB 사용 |
| `PII_CONTEXT_EMBED_MAX_CHARS` | `256` | 문맥 임베딩 대상 최대 길이 |
| `PII_EMBED_DEVICE` | `cpu` | 임베딩 장치. CPU 전용으로 고정 |
| `PII_MODEL_PRELOAD_ENABLED` | `true` | 기동 시 모델 preload |
| `PII_LOG_LEVEL` | `INFO` | 로그 레벨 |
| `PII_STAGE_TIMING_ENABLED` | `false` | 단계별 상세 성능 로그 사용 여부 |
| `PII_LOG_REQUEST_TEXT_ENABLED` | `false` | 요청 원문 로그 사용 여부. 운영 기본값은 비활성화 |
| `PII_LOG_MAX_FILE_MB` | `100` | 단일 애플리케이션 로그 파일 회전 크기 |
| `PII_LOG_TOTAL_MAX_MB` | `10240` | 단일 로그 관리 프로세스가 관리하는 전체 로그 상한 |
| `PII_DOCKER_LOG_MAX_SIZE` | `100m` | 컨테이너 `json-file` 개별 파일 상한 |
| `PII_DOCKER_LOG_MAX_FILE` | `5` | 컨테이너별 `json-file` 보관 개수 |

## Docker Compose

HTTP API 실행:

```bash
docker compose --profile http up -d --build api
```

HTTP API CPU 운영 실행:

```bash
docker compose -f docker-compose.http-cpu.yml --profile http up -d --build api
```

HTTP API HTTPS 실행:

```bash
docker compose -f docker-compose.yml -f docker-compose.https.yml --profile http --profile https up -d --build api https-proxy
```

HTTP API HTTPS 전용 실행:

```bash
docker compose -f docker-compose.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https up -d --build api https-proxy
```

HTTP API CPU HTTPS 실행:

```bash
docker compose -f docker-compose.http-cpu.yml -f docker-compose.https.yml --profile http --profile https up -d --build api https-proxy
```

HTTP API CPU HTTPS 전용 실행:

```bash
docker compose -f docker-compose.http-cpu.yml -f docker-compose.https-only.yml -f docker-compose.https.yml --profile http --profile https up -d --build api https-proxy
```

HTTP API CPU HTTPS 전용 3개 수평확장 실행:

```bash
PII_HTTP_SCALE=3 ./scripts/start_http_cpu_https_only_scale_3.sh
```

HTTP API 종료:

```bash
docker compose --profile http stop api
docker compose --profile http rm -f api
```

gRPC direct 단일 인스턴스 실행:

```bash
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc up -d --build api-grpc
```

gRPC direct 종료:

```bash
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc stop api-grpc
docker compose -f docker-compose.yml -f docker-compose.direct.yml --profile grpc rm -f api-grpc
```

gRPC HAProxy LB 실행:

```bash
docker compose --profile grpc up -d --build api-grpc api-grpc-lb
docker compose --profile grpc up -d --no-build --scale api-grpc=3 api-grpc
```

전체 종료:

```bash
docker compose --profile http --profile grpc down
```

상태 확인:

```bash
docker compose ps
```

로그 확인:

```bash
docker compose logs -f api
docker compose logs -f api-grpc
docker compose logs -f api-grpc-lb
```

이미지 재빌드:

```bash
docker compose --profile http build api
docker compose --profile grpc build api-grpc
```

## Offline Deploy Bundle

배포 패키지는 `VERSION` 값을 Docker 이미지 태그로 사용한다. 버전 변경 후에는 먼저 운영 모드 이미지를 빌드한 뒤 패키지를 만든다.
기본 패키지는 문맥 기반 필터용 HuggingFace 캐시 Docker volume(`xcn-pii_hf_cache`)도 함께 포함한다. 최초 1회는 서비스를 띄운 뒤 문맥 필터가 동작하는 탐지 요청을 실행해 모델 캐시가 생성된 상태에서 패키지를 만든다.

HTTP, HTTPS, gRPC를 모두 포함하는 단일 CPU 패키지:

```bash
docker compose -f docker-compose.http-cpu.yml --profile http build api
docker compose -f docker-compose.grpc-cpu.yml --profile grpc build api-grpc
docker pull haproxy:3.1-alpine
docker pull nginx:1.27-alpine
./scripts/package_deploy_bundle.sh --output-dir ./dist
```

문맥 모델 캐시를 제외해야 하는 경우:

```bash
./scripts/package_deploy_bundle.sh --no-hf-cache --output-dir ./dist
```

생성된 파일은 `dist/xcn-pii-all-cpu-package-<version>-<timestamp>.tar.gz` 형식이며, 압축 내부 최상위 폴더명은 항상 `xcn-pii`이다. 패키지 내부에는 런타임용 기본 `docker-compose.yml` 하나가 포함된다. `install.sh`는 옵션이 없으면 gRPC 모드로 설치하며, `certs/tls.crt`, `certs/tls.key`가 없으면 자체서명 HTTPS 인증서를 생성한다.
gRPC 모드는 기본 `PII_GRPC_SCALE=3`으로 `api-grpc` 3 replica와 HAProxy LB를 기동한다.

신규 서버 설치 및 기동:

```bash
tar -xzf xcn-pii-all-cpu-package-<version>-<timestamp>.tar.gz
cd xcn-pii
./install.sh --no-start
docker compose up -d
```

단일 패키지에서 모드별 설치:

```bash
./install.sh --no-start
docker compose up -d

./install.sh --mode grpc --no-start
docker compose up -d

./install.sh --mode http --no-start
docker compose up -d

./install.sh --mode https --no-start
docker compose up -d
```

`install.sh --mode`는 `.env`에 `COMPOSE_PROFILES`를 기록한다. 이후에는 동일하게 `docker compose up -d`, `docker compose down`을 사용한다.

운영 명령:

```bash
docker compose ps
docker compose logs -f
docker compose down
docker compose up -d
```

기본 포트:

| 서비스 | 포트 |
| --- | --- |
| 기본값 또는 `--mode grpc` | gRPC LB, api-grpc 3 replica | `50055` |
| `--mode http` | HTTP | `8005` |
| `--mode https` | HTTPS | `28443` |
| `--mode all` | HTTP + HTTPS + gRPC LB, api-grpc 3 replica | `8005`, `28443`, `50055` |

## Runtime Patch Bundle

폐쇄망에 이미 기준 이미지가 로드되어 있고 변경 범위가 `.so`, `VERSION`, `app/rules`, `app/static`, `app/proto`, `bin` 같은 런타임 파일에 한정되면 전체 이미지를 다시 전달하지 않고 패치 파일만 전달해 새 이미지 태그를 만들 수 있다.

패치 번들은 기준 이미지와 같은 빌드 환경에서 변경 버전 이미지를 먼저 빌드한 뒤, 빌드된 이미지의 `/app`에서 런타임 파일을 추출해 만든다.

기준 manifest 생성:

```bash
python tools/build_runtime_manifest.py \
  --from-image xcn-pii/api-http-cpu:1.0.0 \
  --profile http-cpu \
  --version 1.0.0 \
  --require-so \
  --output dist/manifests/base-http-cpu-1.0.0.json
```

HTTP CPU 패치 예:

```bash
python tools/build_patch_bundle.py \
  --profile http-cpu \
  --from-image xcn-pii/api-http-cpu:1.0.1-patch1 \
  --version 1.0.1-patch1 \
  --base-image xcn-pii/api-http-cpu:1.0.0 \
  --target-image xcn-pii/api-http-cpu:1.0.1-patch1 \
  --base-manifest dist/manifests/base-http-cpu-1.0.0.json
```

gRPC CPU 패치 예:

```bash
python tools/build_patch_bundle.py \
  --profile grpc-cpu \
  --from-image xcn-pii/api-grpc-cpu:1.0.1-patch1 \
  --version 1.0.1-patch1 \
  --base-image xcn-pii/api-grpc-cpu:1.0.0 \
  --target-image xcn-pii/api-grpc-cpu:1.0.1-patch1 \
  --base-manifest dist/manifests/base-grpc-cpu-1.0.0.json
```

`--base-manifest`를 지정하면 `manifest.json`에 각 파일의 `before_sha256`, `after_sha256`, `action`이 기록된다. 직접 런타임 경로에 적용할 때 대상 파일의 현재 checksum이 `before_sha256`과 다르면 패치를 중단한다.

생성 파일:

```text
dist/patches/<profile>/patch-<profile>-<version>.tar.gz
```

폐쇄망 서버에서는 기준 이미지가 이미 있는 상태에서 패치 이미지를 만든다.

```bash
tar -xzf patch-http-cpu-1.0.1-patch1.tar.gz
./patch-http-cpu-1.0.1-patch1/build_patched_image.sh \
  ./patch-http-cpu-1.0.1-patch1 \
  xcn-pii/api-http-cpu:1.0.0 \
  xcn-pii/api-http-cpu:1.0.1-patch1
```

또는 압축 파일을 직접 지정할 수 있다.

```bash
./scripts/build_patched_image.sh \
  ./dist/patches/http-cpu/patch-http-cpu-1.0.1-patch1.tar.gz \
  xcn-pii/api-http-cpu:1.0.0 \
  xcn-pii/api-http-cpu:1.0.1-patch1
```

패치 적용 후 `.env`의 `PII_IMAGE_TAG`를 새 태그로 변경하고 서비스를 재기동한다.

```bash
PII_IMAGE_TAG=1.0.1-patch1
```

주의:

- Python 버전, OS 패키지, `requirements*.txt`, Cython ABI, torch/semantic dependency가 바뀌면 전체 이미지 재빌드와 배포가 필요하다.
- `.so`는 반드시 기준 이미지와 같은 Python/runtime 환경에서 빌드해야 한다.
- manifest의 파일 해시가 맞지 않으면 패치 이미지 빌드 전에 중단된다.
- 가능하면 `--base-manifest`를 사용해 적용 전 checksum preflight를 수행한다.

## Start/Stop Scripts

공통 실행 스크립트:

```bash
./scripts/start_services.sh http
./scripts/start_services.sh grpc
./scripts/start_services.sh all
```

gRPC scale과 worker 수 지정:

```bash
./scripts/start_services.sh grpc 3 6
./scripts/start_services.sh all 3 6
```

공통 종료 스크립트:

```bash
./scripts/stop_services.sh http
./scripts/stop_services.sh grpc
./scripts/stop_services.sh all
```

HTTP CPU 운영:

```bash
./scripts/start_http_cpu.sh
./scripts/stop_http_cpu.sh
```

HTTPS 인증서 생성:

```bash
./scripts/make_self_signed_cert.sh localhost
./scripts/make_self_signed_cert.sh pii.example.com 3650
```

운영 인증서를 사용할 경우 아래 파일명으로 배치한다.

```text
certs/tls.crt
certs/tls.key
```

HTTP HTTPS 운영:

```bash
./scripts/start_http_https.sh
./scripts/stop_http_https.sh
```

HTTP HTTPS 전용 운영:

```bash
./scripts/start_http_https_only.sh
./scripts/stop_http_https_only.sh
```

HTTP CPU HTTPS 운영:

```bash
./scripts/start_http_cpu_https.sh
./scripts/stop_http_cpu_https.sh
```

HTTP CPU HTTPS 전용 운영:

```bash
./scripts/start_http_cpu_https_only.sh
./scripts/stop_http_cpu_https_only.sh
```

HTTP CPU HTTPS 전용 3개 수평확장 운영:

```bash
PII_HTTP_SCALE=3 ./scripts/start_http_cpu_https_only_scale_3.sh
./scripts/stop_http_cpu_https_only_scale.sh
```

gRPC direct CPU:

```bash
./scripts/start_grpc_direct.sh
./scripts/start_grpc_direct.sh 6
./scripts/stop_grpc_direct.sh
```

gRPC HAProxy LB CPU:

```bash
./scripts/start_grpc_lb_3.sh
./scripts/start_grpc_lb_3.sh 6
./scripts/stop_grpc_lb_3.sh
```

## Local Python

가상환경 생성 및 패키지 설치:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -r requirements.txt
```

HTTP API 로컬 실행:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8005
```

gRPC 서버 로컬 실행:

```bash
python -m app.grpc_server
```

문맥 필터 데모:

```bash
python app/test_context_filter.py
```

pytest 실행:

```bash
pytest
pytest app/test_mn_detection.py
pytest app/test_refactor_smoke.py
```

## HTTP API

기본 UI:

```bash
curl http://localhost:8005/
```

PII 탐지:

```bash
curl -X POST "http://localhost:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: default" \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
    "max_results_per_type": 100
  }'
```

HTTPS PII 탐지:

```bash
curl -k -X POST "https://localhost:28443/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: default" \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
    "max_results_per_type": 100
  }'
```

strict 룰셋으로 탐지:

```bash
curl -X POST "http://localhost:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: strict" \
  -d '{
    "text": "연락처는 010-1234-5678 입니다.",
    "max_results_per_type": 100
  }'
```

베트남 개인정보 탐지:

```bash
curl -X POST "http://localhost:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: default" \
  -d '{
    "text": "CCCD: 001234567890, so dien thoai 098-123-4567, ho chieu B12345678, ma so thue 0312345678-001, ma so BHXH 0123456789",
    "max_results_per_type": 100
  }'
```

파일 탐지:

```bash
curl -X POST "http://localhost:8005/pii/detect/file" \
  -H "X-PII-RULESET: default" \
  -F "file=@./sample.txt" \
  -F "max_results_per_type=500"
```

룰셋 목록:

```bash
curl http://localhost:8005/pii/rulesets
```

selftest:

```bash
curl http://localhost:8005/pii/selftest
```

문맥 탐지 debug:

```bash
curl -X POST "http://localhost:8005/debug/context" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "담당자 홍길동의 휴대폰 번호는 010-1234-5678 입니다.",
    "ruleset": "default"
  }'
```

## gRPC API

Direct endpoint:

```text
localhost:50051
```

LB endpoint:

```text
localhost:50055
```

Health:

```bash
grpcurl -plaintext localhost:50051 xcn.pii.v1.PiiDetector/Health
```

Detect direct:

```bash
grpcurl -plaintext \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567 입니다.",
    "max_results_per_type": 100,
    "ruleset": "default"
  }' \
  localhost:50051 xcn.pii.v1.PiiDetector/Detect
```

Detect LB:

```bash
grpcurl -plaintext \
  -d '{
    "text": "연락처는 010-1234-5678 입니다.",
    "max_results_per_type": 100,
    "ruleset": "default"
  }' \
  localhost:50055 xcn.pii.v1.PiiDetector/Detect
```

Vietnam PII Detect LB:

```bash
grpcurl -plaintext \
  -d '{
    "text": "CCCD: 001234567890, so dien thoai 098-123-4567, ho chieu B12345678, ma so thue 0312345678-001, ma so BHXH 0123456789",
    "max_results_per_type": 100,
    "ruleset": "default"
  }' \
  localhost:50055 xcn.pii.v1.PiiDetector/Detect
```

## Benchmark

기본 gRPC benchmark:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --requests 500 --concurrency 20 --channels 8
```

Direct endpoint benchmark:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50051 --requests 100 --warmup-requests 10 --concurrency 10 --channels 10
```

시간 기준 benchmark:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --duration-sec 30 --requests -1 --concurrency 40 --channels 16
```

payload 파일 사용:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --payload-file ./sample.txt --requests 200
```

payload 문자열 직접 지정:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --payload-text "홍길동 010-1234-5678" --requests 100
```

strict 룰셋 benchmark:

```bash
py -3 ./scripts/grpc_benchmark.py --target 127.0.0.1:50055 --ruleset strict --requests 200
```

동일 payload와 영속 연결을 사용한 HTTP/gRPC 비교 benchmark:

```bash
python scripts/protocol_benchmark.py \
  --http-target http://xcn-pii-api:8000/pii/detect \
  --grpc-direct-target 127.0.0.1:50051 \
  --grpc-lb-target xcn-pii-grpc-lb:50051 \
  --requests 100 \
  --warmup-requests 20 \
  --concurrency 4
```

기본 입력은 끝부분에 유효한 BRN이 있는 52,042자 문자열이며, 성공 응답뿐 아니라 `BRN_CNT=1`도
검증한다. 단일 gRPC 인스턴스의 기본 수용량은 탐지 worker 4개와 대기 1개이므로 직접 endpoint에
5를 초과하는 동시성을 주면 과부하 보호에 의해 일부 요청이 거절될 수 있다. 높은 동시성 비교는
3 replica LB endpoint를 기준으로 수행한다.

## Context Threshold Evaluation

문맥 threshold 평가:

```bash
python tools/eval_context_thresholds.py \
  --data tools/context_eval.json \
  --url http://localhost:8005/pii/detect \
  --min 0.0 \
  --max 1.0 \
  --step 0.05 \
  --out-rows tools/context_eval_rows.csv \
  --out-summary tools/context_eval_summary.csv
```

HTTP 서비스를 사용하지 않는 로컬 평가:

```bash
python tools/eval_context_thresholds.py --local
```

기본 `tools/context_eval.json`은 17개 문맥 대상 유형별로 양성 4건·음성 4건, 총 136건의
기본·경계·교란 사례를 확인하는 합성 평가셋이다. 운영 threshold를 갱신하는 근거로 사용하지
않는다. 운영 설정 갱신은 비식별
대표 데이터셋의 `dataset_kind`를 `representative`로 지정하고 결과를 검토한 뒤에만 명시한다.

```bash
python tools/eval_context_thresholds.py \
  --data tools/context_eval_representative.json \
  --url http://localhost:8005/pii/detect \
  --update-context app/rules/context.yaml
```

임베딩 모델 로드에 실패해 keyword fallback으로만 평가된 경우 도구는 embedding score가
없다는 경고를 출력하며 `--update-context`를 차단한다.

## Ports

| 모드 | 외부 포트 | 내부 포트 | 설명 |
| --- | ---: | ---: | --- |
| HTTP | `8005` | `8000` | FastAPI HTTP/JSON |
| HTTPS | `28443` | `443` | Nginx TLS proxy to HTTP API |
| gRPC direct | `50051` | `50051` | 단일 gRPC 서버 |
| gRPC LB | `50055` | `50051` | HAProxy LB |

## Common Checks

컨테이너 목록:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

HTTP API 응답 확인:

```bash
curl -s http://localhost:8005/pii/selftest
```

gRPC LB 로그 확인:

```bash
docker logs -f xcn-pii-grpc-lb
```

HTTP 로그 파일 확인:

```bash
tail -f logs/*.log
```

리소스 사용량 확인:

```bash
docker stats
```

## Recommended Modes

개발 또는 단일 서버 단순 배포:

```bash
./scripts/start_grpc_direct.sh 6
```

운영 성능 확인용 3 replica LB:

```bash
./scripts/start_grpc_lb_3.sh 6
```

HTTP API만 외부 연동할 때:

```bash
./scripts/start_services.sh http
```

HTTP API를 CPU로만 운영할 때:

```bash
./scripts/start_http_cpu.sh
```

HTTP API를 HTTPS로 운영할 때:

```bash
./scripts/start_http_https.sh
```

HTTP 외부 포트를 닫고 HTTPS만 열 때:

```bash
./scripts/start_http_https_only.sh
```

HTTP API를 CPU + HTTPS로 운영할 때:

```bash
./scripts/start_http_cpu_https.sh
```

HTTP 외부 포트를 닫고 CPU + HTTPS만 열 때:

```bash
./scripts/start_http_cpu_https_only.sh
```

HTTP 외부 포트를 닫고 CPU + HTTPS API를 3개로 수평확장할 때:

```bash
PII_HTTP_SCALE=3 ./scripts/start_http_cpu_https_only_scale_3.sh
```

이 모드는 `docker-compose.http-scale.yml`로 `api`의 고정 `container_name`과 HTTP host port publish를 제거한다. HTTPS proxy는 Docker DNS로 `api:8000`을 재해석하므로 `api` 3개 중 1개가 중지되면 남은 2개로 요청을 처리한다.
