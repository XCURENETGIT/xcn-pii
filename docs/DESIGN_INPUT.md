# xcn-pii-full 설계서 작성 입력 자료

## 1. 문서 목적

본 문서는 `xcn-pii-full` 프로젝트의 현재 개발 내용을 기준으로 설계서 작성에 필요한 정보를 정리한 입력 자료이다. 최종 설계서는 본 문서의 내용을 기반으로 별도 작성한다.

## 2. 시스템 개요

`xcn-pii-full`은 텍스트 및 파일에서 개인정보 후보를 탐지하는 PII 탐지 시스템이다. 주요 기능은 다음과 같다.

- HTTP/JSON API 제공
- gRPC API 제공
- 정규식 및 Hyperscan 기반 고속 탐지
- 주민등록번호 등 일부 항목에 대한 구조 검증
- MN, BN 등 오탐 가능 항목에 대한 후처리 필터
- 문맥 기반 post-filter
- 긴 텍스트 split 처리
- long payload fast-path 처리
- 파일 업로드 후 텍스트 추출 기반 탐지
- 룰셋 hot reload 및 `default`/`strict` 룰셋 전환
- CPU/GPU 실행 모드
- HTTPS reverse proxy 구성
- gRPC direct/LB/Envoy 구성

## 3. 주요 디렉터리

| 경로 | 설명 |
| --- | --- |
| `app/main.py` | FastAPI HTTP 진입점 |
| `app/grpc_server.py` | gRPC 서버 진입점 |
| `app/pii.py` | public detection API 및 split 처리 |
| `app/pii_engine/` | 탐지 엔진, pipeline, detector, context filter |
| `app/rules/` | 룰셋 및 항목별 탐지 규칙 |
| `app/proto/pii.proto` | gRPC 서비스 정의 |
| `app/file_text_extract.py` | 파일 텍스트 추출 래퍼 |
| `app/guardrail.py` | SGuard 기반 guardrail 옵션 |
| `app/static/` | HTTP UI 정적 리소스 |
| `infra/haproxy/` | gRPC HAProxy LB 설정 |
| `infra/envoy/` | gRPC Envoy LB 설정 |
| `infra/nginx/` | HTTPS proxy 설정 |
| `scripts/` | 실행/종료/벤치마크 스크립트 |
| `docs/` | API, 명령어, 설계 관련 문서 |

## 4. 외부 인터페이스

### 4.1 HTTP API

기본 포트는 `8005`이다.

| Method | Path | 설명 |
| --- | --- | --- |
| `GET` | `/` | 정적 UI 반환 |
| `POST` | `/pii/detect` | 텍스트 PII 탐지 |
| `POST` | `/pii/detect/file` | 업로드 파일 텍스트 추출 후 PII 탐지 |
| `GET` | `/pii/rulesets` | 룰셋 목록 조회 |
| `GET` | `/pii/selftest` | 내장 샘플 selftest |
| `POST` | `/debug/context` | 문맥 탐지 디버그 |

### 4.2 gRPC API

서비스명은 `xcn.pii.v1.PiiDetector`이다.

| RPC | 설명 |
| --- | --- |
| `Health` | gRPC 서버 상태 확인 |
| `Detect` | 텍스트 PII 탐지 |

기본 endpoint:

- direct: `localhost:50051`
- LB: `localhost:50055`

### 4.3 HTTPS API

HTTPS는 FastAPI 직접 TLS가 아니라 Nginx reverse proxy에서 TLS를 종료한다.

| 항목 | 값 |
| --- | --- |
| compose 파일 | `docker-compose.https.yml` |
| HTTPS-only override | `docker-compose.https-only.yml` |
| proxy 서비스 | `https-proxy` |
| 기본 외부 포트 | `28443` |
| 인증서 경로 | `certs/tls.crt`, `certs/tls.key` |
| Nginx 설정 | `infra/nginx/https.conf.template` |

## 5. 요청/응답 모델

### 5.1 DetectPiiRequest

| 필드 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `text` | string | 1 ~ 10,000,000 chars | 탐지 대상 텍스트 |
| `max_results_per_type` | int | 1 ~ 5000, 기본 500 | 타입별 최대 결과 수 |

### 5.2 MatchItem

| 필드 | 설명 |
| --- | --- |
| `start` | 원문 기준 시작 offset |
| `end` | 원문 기준 종료 offset |
| `matchString` | 매치 문자열 |
| `isValid` | 구조/체크섬 검증 결과 |
| `context_score` | 문맥 점수 |
| `context_score_norm` | 정규화 문맥 점수 |
| `context_hybrid_score` | hybrid 문맥 점수 |
| `context_method` | 문맥 탐지 방식 |
| `context_accept_by` | 통과 기준 |
| `context_pass` | 문맥 필터 통과 여부 |
| `detected_by` | 탐지 방식 |

### 5.3 PII 타입

| 타입 | 의미 |
| --- | --- |
| `SN` | 주민등록번호 |
| `SSN` | Social Security Number |
| `DN` | 운전면허번호 |
| `PN` | 여권번호 |
| `MN` | 휴대전화/전화번호 |
| `BN` | 계좌번호/은행 관련 번호 |
| `CN` | 카드번호 |
| `EML` | 이메일 |

## 6. 탐지 엔진 구조

### 6.1 진입 흐름

1. HTTP 또는 gRPC 요청 수신
2. 요청 텍스트와 룰셋 결정
3. `app.pii.detect_with_meta()` 호출
4. 긴 텍스트인 경우 split 처리
5. 룰셋별 `PiiEngine` 로딩 또는 캐시 조회
6. pipeline detector 순차 실행
7. 후처리 및 context filter 적용
8. offset remap 및 빈 결과 제거
9. API 응답 생성

### 6.2 Engine registry

`app/pii_engine/engine.py`는 `(rules_dir, ruleset)` 키로 `PiiEngine`을 캐시한다.

- 최초 요청 시 룰셋 로드 및 pipeline 생성
- 룰 변경 감지 시 hot reload
- `preload_models()`로 기동 시 룰셋/문맥 모델 preload 가능

### 6.3 Split 처리

`app/pii.py`는 긴 텍스트에 대해 chunk 단위 split 처리를 수행한다.

관련 환경 변수:

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `PII_SPLIT_ENABLED` | `true` | split 사용 여부 |
| `PII_SPLIT_TEXT_LEN` | `50000` | split 시작 길이 |
| `PII_SPLIT_CHUNK_CHARS` | `50000` | chunk 크기 |
| `PII_SPLIT_OVERLAP_CHARS` | `2000` | chunk overlap |
| `PII_SPLIT_MAX_WORKERS` | `1` | parallel worker 수 |
| `PII_SPLIT_MAX_RESULTS_PER_TYPE` | `200` | chunk별 타입 결과 제한 |
| `PII_SPLIT_MAX_CHUNKS` | `64` | 최대 chunk 수 |

### 6.4 Fast-path

긴 텍스트에서 탐지 범위와 결과 수를 제한하여 성능을 확보한다.

관련 환경 변수:

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `PII_FASTPATH_ENABLED` | `true` | fast-path 사용 여부 |
| `PII_FASTPATH_TEXT_LEN` | `50000` | fast-path 시작 길이 |
| `PII_FASTPATH_MAX_RESULTS_PER_TYPE` | `200` | 타입별 결과 제한 |
| `PII_FASTPATH_TARGET_KEYS` | `SN,SSN,DN,PN,MN,EML,CN` | fast-path 대상 타입 |

## 7. 룰셋

### 7.1 default

파일: `app/rules/_ruleset.yaml`

pipeline 순서:

```text
dn -> SSN -> sn -> pn -> EML -> cn -> mn -> bn -> post_mn -> post_bn -> post_context
```

특징:

- `context.yaml`을 포함한다.
- 문맥 post-filter가 적용된다.
- `BN`은 `bn.yaml`을 사용한다.

### 7.2 strict

파일: `app/rules/_ruleset_strict.yaml`

pipeline 순서:

```text
SSN -> sn -> dn -> pn -> EML -> cn -> mn -> bn -> post_mn -> post_bn
```

특징:

- `post_context` 단계가 없다.
- `BN`은 `bn_strict.yaml`을 사용한다.
- 더 엄격한 탐지/후처리 룰을 적용하는 용도이다.

## 8. 탐지 방식 요약

| 타입 | 주요 탐지 방식 | 추가 검증/후처리 | 문맥 필터 대상 |
| --- | --- | --- | --- |
| `SN` | Hyperscan 우선, regex fallback | 주민등록번호 checksum | default에서 대상 |
| `SSN` | Hyperscan 우선, regex fallback | 구조 검증 | default에서 대상 |
| `DN` | Hyperscan 우선, regex fallback | verify regex | default에서 대상 |
| `PN` | Hyperscan 우선, regex fallback | verify regex | default에서 대상 |
| `MN` | Hyperscan 우선, regex fallback | 전화번호 구조, 경계 숫자, overlap reject | 룰 파일에는 설정 존재, default target에서는 제외 |
| `BN` | regex | 길이/전화번호/주민번호 유사/overlap reject | default에서 대상 |
| `CN` | Hyperscan 우선, regex fallback | 카드번호 구조 검증 | default에서 대상 |
| `EML` | Hyperscan 우선, regex fallback | 이메일 구조 검증 | 룰 파일에는 설정 존재, default target에서는 제외 |

## 9. 문맥 필터

파일: `app/rules/context.yaml`

현재 설정:

- `enabled: true`
- `method: embed`
- model: `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`
- global threshold: `0.55`
- window sentences: `2`
- default target keys: `SN`, `SSN`, `DN`, `PN`, `BN`, `CN`
- hybrid scoring enabled

문맥 필터는 semantic similarity와 label/header/repeat/digit hint를 조합해 오탐을 줄인다.

## 10. 파일 탐지

`POST /pii/detect/file`은 업로드 파일을 임시 파일로 저장하고 `xutf_8` 바이너리로 텍스트를 추출한다.

관련 파일:

- `app/file_text_extract.py`
- `bin/xutf_8`

관련 환경 변수:

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `XUTF8_BINARY_PATH` | `/app/bin/xutf_8` | 텍스트 추출 바이너리 경로 |
| `XUTF8_TIMEOUT_SEC` | `60` | 추출 timeout |

## 11. Guardrail

`app/guardrail.py`는 SGuard 기반 안전성 평가를 옵션으로 제공한다.

기본값:

- `PII_GUARDRAIL_ENABLED=false`
- provider: `sguard`
- device: `cuda`
- fail open: `true`

CPU HTTP 운영 모드에서는 guardrail을 비활성화하고 device를 CPU로 강제한다.

## 12. 배포 구성

### 12.1 HTTP

파일:

- `Dockerfile.http`
- `docker-compose.yml`

서비스:

- `api`
- host port: `8005`
- container port: `8000`

### 12.2 HTTP CPU

파일:

- `docker-compose.http-cpu.yml`
- `scripts/start_http_cpu.sh`
- `scripts/stop_http_cpu.sh`

특징:

- `PII_EMBED_DEVICE=cpu`
- `PII_GUARDRAIL_ENABLED=false`
- `NVIDIA_VISIBLE_DEVICES=void`
- GPU reservation 없음

### 12.3 HTTPS

파일:

- `docker-compose.https.yml`
- `docker-compose.https-only.yml`
- `docker-compose.http-scale.yml`
- `infra/nginx/https.conf.template`
- `scripts/start_http_https.sh`
- `scripts/start_http_https_only.sh`
- `scripts/start_http_cpu_https.sh`
- `scripts/start_http_cpu_https_only.sh`

특징:

- Nginx reverse proxy TLS termination
- `https-proxy -> api:8000`
- 기본 외부 포트 `28443`
- HTTPS-only 모드에서는 `api`의 HTTP host port를 publish하지 않고 Docker network 내부 `8000`만 노출
- HTTP scale 모드에서는 `api`의 고정 `container_name`을 제거하고 `--scale api=<N>`으로 다중 replica를 실행

### 12.4 gRPC

파일:

- `Dockerfile.grpc`
- `docker-compose.yml`
- `docker-compose.direct.yml`
- `infra/haproxy/grpc-lb.cfg`
- `infra/envoy/grpc-lb.yaml`

모드:

- direct: `50051`
- HAProxy LB: `50055`
- Envoy LB: `50055`
- CPU/GPU 스크립트 제공

## 13. 실행 스크립트

| 스크립트 | 설명 |
| --- | --- |
| `start_services.sh` | HTTP/gRPC/all 공통 실행 |
| `stop_services.sh` | HTTP/gRPC/all 공통 종료 |
| `start_http_cpu.sh` | HTTP CPU 실행 |
| `stop_http_cpu.sh` | HTTP CPU 종료 |
| `make_self_signed_cert.sh` | self-signed TLS 인증서 생성 |
| `start_http_https.sh` | HTTP + HTTPS 실행 |
| `stop_http_https.sh` | HTTP + HTTPS 종료 |
| `start_http_https_only.sh` | HTTPS 전용 실행 |
| `stop_http_https_only.sh` | HTTPS 전용 종료 |
| `start_http_cpu_https.sh` | HTTP CPU + HTTPS 실행 |
| `stop_http_cpu_https.sh` | HTTP CPU + HTTPS 종료 |
| `start_http_cpu_https_only.sh` | HTTP CPU HTTPS 전용 실행 |
| `stop_http_cpu_https_only.sh` | HTTP CPU HTTPS 전용 종료 |
| `start_http_cpu_https_only_scale_3.sh` | HTTP CPU HTTPS 전용 3개 수평확장 실행 |
| `stop_http_cpu_https_only_scale.sh` | HTTP CPU HTTPS 전용 수평확장 종료 |
| `start_grpc_direct.sh` | gRPC direct CPU 실행 |
| `start_grpc_gpu_direct.sh` | gRPC direct GPU 실행 |
| `start_grpc_lb_3.sh` | gRPC HAProxy LB CPU 3 replica 실행 |
| `start_grpc_gpu_lb_3.sh` | gRPC HAProxy LB GPU 3 replica 실행 |
| `start_grpc_envoy_3.sh` | gRPC Envoy LB 3 replica 실행 |
| `grpc_benchmark.py` | gRPC 성능 측정 |

## 14. 로깅 및 관측

관련 파일:

- `app/logging_utils.py`

주요 로그:

- 요청 길이, bytes, 룰셋, max_results
- 전체 탐지 시간
- stage별 timing
- 타입별 kept count
- gRPC 요청 timing

관련 환경 변수:

| 변수 | 기본값 |
| --- | --- |
| `PII_LOG_LEVEL` | `INFO` |
| `PII_FILE_LOG_ENABLED` | `true` |
| `PII_LOG_DIR` | `/logs` |
| `PII_LOG_BACKUP_DAYS` | `30` |
| `PII_STAGE_TIMING_ENABLED` | `true` |
| `PII_STAGE_LOG_ENABLED` | `false` |
| `PII_TRACE_DETECT` | `false` |

## 15. 성능 관련 구성

- Hyperscan combined DB로 다수 타입을 공유 scan 가능
- gRPC worker 수 조정 가능
- long payload split 처리
- fast-path로 긴 텍스트 대상 detector 제한
- 문맥 embedding preload 지원
- gRPC benchmark 도구 제공

## 16. 보안 관련 구성

- HTTPS reverse proxy 지원
- 운영 인증서 마운트 방식
- `certs/`는 `.gitignore` 처리
- 공개 API 자체 인증은 없음
- 외부 공개 시 API Gateway, WAF, mTLS, 사설망 제한 권장
- guardrail은 옵션이며 기본 비활성화

## 17. 설계서 작성 시 포함해야 할 항목

- 시스템 목적 및 범위
- 전체 아키텍처
- HTTP/gRPC/HTTPS 인터페이스
- 탐지 pipeline 설계
- 룰셋 구조
- 항목별 탐지 방식
- 문맥 필터 설계
- 긴 텍스트 처리
- 파일 탐지 처리
- 배포/운영 구성
- 환경 변수
- 로깅/관측
- 보안 고려사항
- 성능 고려사항
- 제약 및 향후 개선사항
