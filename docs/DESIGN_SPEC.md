# xcn-pii-full 시스템 설계서

| 문서명 | xcn-pii-full 시스템 설계서 |
| --- | --- |
| 대상 시스템 | xcn-pii-full |
| 작성 기준 | 현재 개발 코드 기준 |
| 작성일 | 2026-04-17 |
| 문서 유형 | 시스템/응용/배포 설계서 |

## 1. 개요

### 1.1 목적

본 문서는 `xcn-pii-full` 시스템의 현재 구현 내용을 기준으로 시스템 구조, 인터페이스, 탐지 엔진, 룰셋, 배포 및 운영 구성을 정의한다. 본 문서는 개발자, 운영자, 연동 시스템 담당자가 시스템을 이해하고 유지보수할 수 있도록 작성되었다.

### 1.2 시스템 범위

`xcn-pii-full`은 입력 텍스트 또는 업로드 파일에서 개인정보 후보를 탐지하는 시스템이다. 시스템은 HTTP/JSON API, gRPC API, HTTPS proxy 구성을 제공하며, 정규식, Hyperscan, 구조 검증, 후처리 필터, 문맥 필터를 조합하여 탐지 결과를 생성한다.

### 1.3 주요 기능

- 텍스트 기반 개인정보 탐지
- 파일 업로드 기반 개인정보 탐지
- HTTP/JSON API 제공
- gRPC API 제공
- HTTPS reverse proxy 제공
- 룰셋 기반 탐지 pipeline 구성
- `default`, `strict` 룰셋 전환
- Hyperscan 기반 고속 탐지
- Python regex fallback
- 주민등록번호 checksum 검증
- 전화번호/계좌번호 후처리
- 문맥 기반 post-filter
- 긴 텍스트 split 처리
- long payload 전체 범위 split 처리
- CPU 전용 운영 모드
- gRPC direct/LB 운영 모드
- 성능 측정 스크립트 제공

## 2. 시스템 구성

### 2.1 논리 아키텍처

```text
Client
  |
  | HTTP / HTTPS / gRPC
  v
Interface Layer
  - FastAPI HTTP
  - gRPC Server
  - Nginx HTTPS Proxy
  |
  v
Application Layer
  - request validation
  - ruleset selection
  - file text extraction
  - response building
  |
  v
Detection Layer
  - split processing
  - engine registry
  - detector pipeline
  - Hyperscan / regex
  - post filters
  - contextual filters
  |
  v
Rule / Model Layer
  - YAML rule files
  - context config
  - sentence-transformers model
```

### 2.2 물리 구성

| 구성 요소 | 구현 파일/서비스 | 설명 |
| --- | --- | --- |
| HTTP API | `app/main.py`, `api` | FastAPI 기반 HTTP API |
| gRPC API | `app/grpc_server.py`, `api-grpc` | gRPC 기반 탐지 API |
| HTTPS Proxy | `https-proxy` | Nginx TLS termination |
| 탐지 엔진 | `app/pii_engine/` | pipeline 기반 탐지 |
| 룰셋 | `app/rules/` | YAML 기반 탐지 룰 |
| 파일 추출 | `app/file_text_extract.py`, `bin/xutf_8` | 업로드 파일 텍스트 추출 |
| 문맥 모델 | sentence-transformers | semantic context filter |

## 3. 인터페이스 설계

### 3.1 HTTP API

기본 포트는 `8005`이다.

| Method | Path | 설명 |
| --- | --- | --- |
| `GET` | `/` | 정적 UI 반환 |
| `POST` | `/pii/detect` | 텍스트 개인정보 탐지 |
| `POST` | `/pii/detect/file` | 파일 업로드 후 개인정보 탐지 |
| `GET` | `/pii/rulesets` | 서버 룰셋 목록 조회 |
| `GET` | `/pii/selftest` | 내장 샘플 탐지 |
| `POST` | `/debug/context` | 문맥 탐지 디버그 |

### 3.2 HTTP 요청 모델

`POST /pii/detect`

| 필드 | 타입 | 필수 | 제약 | 설명 |
| --- | --- | --- | --- | --- |
| `text` | string | Y | 1 ~ 10,000,000 chars | 탐지 대상 텍스트 |
| `max_results_per_type` | integer | N | 1 ~ 5000 | 타입별 최대 결과 수 |

룰셋은 HTTP header로 지정한다.

```text
X-PII-RULESET: default
X-PII-RULESET: strict
```

헤더가 없으면 환경 변수 `PII_RULESET` 또는 기본값 `default`가 적용된다.

### 3.3 HTTP 응답 모델

응답은 다음 구조를 따른다.

| 필드 | 설명 |
| --- | --- |
| `success` | 처리 성공 여부 |
| `status` | 상태 코드 |
| `data` | PII 타입별 탐지 결과 |
| `meta` | 룰셋 메타 정보 |

PII 타입별 결과는 `SN_CNT`, `SN`처럼 count와 배열의 쌍으로 반환된다. 결과가 없는 타입은 응답에서 생략될 수 있다.

### 3.4 MatchItem

| 필드 | 설명 |
| --- | --- |
| `start` | 원문 기준 시작 offset |
| `end` | 원문 기준 종료 offset |
| `matchString` | 매치 문자열 |
| `isValid` | 구조 또는 checksum 검증 결과 |
| `context_score` | 문맥 점수 |
| `context_score_norm` | 정규화 문맥 점수 |
| `context_hybrid_score` | hybrid 문맥 점수 |
| `context_method` | 문맥 평가 방식 |
| `context_accept_by` | 문맥 통과 기준 |
| `context_pass` | 문맥 필터 통과 여부 |
| `detected_by` | 탐지 방식 |

### 3.5 gRPC API

gRPC 서비스명은 `xcn.pii.v1.PiiDetector`이다.

| RPC | 설명 |
| --- | --- |
| `Health` | 서버 상태 확인 |
| `Detect` | 텍스트 개인정보 탐지 |

기본 endpoint:

| 모드 | Endpoint |
| --- | --- |
| direct | `localhost:50051` |
| LB | `localhost:50055` |

### 3.6 HTTPS API

HTTPS는 애플리케이션 서버가 직접 처리하지 않고 Nginx reverse proxy에서 TLS를 종료한다. proxy는 내부 Docker network의 `api:8000`으로 요청을 전달한다.

| 항목 | 값 |
| --- | --- |
| compose 파일 | `docker-compose.https.yml` |
| HTTPS-only override | `docker-compose.https-only.yml` |
| 서비스명 | `https-proxy` |
| 기본 포트 | `28443` |
| 인증서 | `certs/tls.crt`, `certs/tls.key` |
| 설정 파일 | `infra/nginx/https.conf.template` |

## 4. 탐지 엔진 설계

### 4.1 처리 흐름

```text
Request 수신
  -> 입력 검증
  -> 룰셋 결정
  -> detect_with_meta 호출
  -> 긴 텍스트 split 여부 판단
  -> PiiEngine 획득
  -> pipeline 실행
  -> 후처리 필터 실행
  -> 문맥 필터 실행
  -> offset remap
  -> 빈 결과 제거
  -> 응답 생성
```

### 4.2 Engine registry

탐지 엔진은 `(rules_dir, ruleset)` 키로 캐시된다. 동일 룰셋 요청은 기존 `PiiEngine`을 재사용한다. 룰 파일 변경이 감지되면 룰셋을 다시 로드하고 pipeline을 재생성한다.

주요 책임:

- 룰셋 로딩
- pipeline 생성
- engine 캐싱
- hot reload
- 모델 preload

### 4.3 Pipeline

Pipeline은 룰셋의 `steps` 순서에 따라 detector 객체를 생성하고 순차 실행한다.

`default` pipeline:

```text
dn -> SSN -> sn -> pn -> EML -> cn -> mn -> bn -> post_mn -> post_bn -> post_context
```

`strict` pipeline:

```text
SSN -> sn -> dn -> pn -> EML -> cn -> mn -> bn -> post_mn -> post_bn
```

### 4.4 Detector 유형

| Detector | 설명 |
| --- | --- |
| `HSRegexDetector` | Hyperscan 우선 탐지, verify regex 및 supplement regex 지원 |
| `SNHSDetector` | 주민등록번호 Hyperscan 탐지 및 checksum 검증 |
| `SNDetector` | 주민등록번호 regex 탐지 및 checksum 검증 |
| `RegexDetector` | Python regex 기반 탐지 |
| `DNDetector` | 운전면허번호 Hyperscan 탐지 |
| `MNPostFilter` | 전화번호 후보 후처리 |
| `BNPostFilter` | 계좌번호 후보 후처리 |
| `ContextualLLMPostFilter` | sentence-transformers embedding 기반 문맥 필터. 이름은 기존 호환성 유지용이며 생성형 LLM 호출은 수행하지 않음 |
| `ContextualPostFilter` | keyword 기반 문맥 필터 |

### 4.5 Hyperscan 및 Regex fallback

Hyperscan 사용 가능 패턴은 사전 검증 후 DB로 컴파일된다. Hyperscan에서 지원하지 않는 패턴은 Python regex supplement 또는 fallback으로 처리한다.

성능 최적화를 위해 `PII_HS_COMBINED_ENABLED=true`인 경우 여러 타입의 Hyperscan 패턴을 하나의 combined DB로 묶어 공유 scan을 수행한다.

## 5. 항목별 탐지 설계

| 타입 | 설명 | 주요 탐지 방식 | 검증/후처리 | 문맥 필터 |
| --- | --- | --- | --- | --- |
| `SN` | 주민등록번호 | Hyperscan 우선, regex fallback | checksum 검증 | default 대상 |
| `FN` | 외국인등록번호 | SN 후보 스캔 후 분리 | checksum 검증, 뒤 7자리 첫 숫자 `5`~`8` | default 대상 |
| `SSN` | Social Security Number | Hyperscan 우선, regex fallback | 구조 검증 | default 대상 |
| `DN` | 운전면허번호 | Hyperscan 우선, regex fallback | verify regex | default 대상 |
| `PN` | 여권번호 | Hyperscan 우선, regex fallback | verify regex | default 대상 |
| `MN` | 전화번호 | Hyperscan 우선, regex fallback | 전화번호 구조, 경계 숫자, overlap reject | 룰에는 설정 존재, default target에서는 제외 |
| `BRN` | 사업자등록번호 | Hyperscan 우선, regex fallback | 사업자등록번호 구조 검증 | 룰에는 설정 존재, default target에서는 제외 |
| `BN` | 계좌번호/은행번호 | regex | 길이, 전화번호 유사, 주민번호 유사, overlap reject | default 대상 |
| `AN` | 주소 | regex | 주소 구성요소 검증 | 룰에는 설정 존재, default target에서는 제외 |
| `CN` | 카드번호 | Hyperscan 우선, regex fallback | 카드번호 구조 검증 | default 대상 |
| `EML` | 이메일 | Hyperscan 우선, regex fallback | 이메일 구조 검증 | 룰에는 설정 존재, default target에서는 제외 |
| `VN_CCCD` | 베트남 시민신분증/개인식별번호 | Hyperscan 우선, regex fallback | 12자리 및 성/시 코드 prefix 검증 | default 대상 |
| `VN_MN` | 베트남 휴대폰번호 | Hyperscan 우선, regex fallback | 이동통신사 prefix 및 10자리 구조 검증 | default 대상 |
| `VN_PN` | 베트남 여권번호 | Hyperscan 우선, regex fallback | 영문 1자리 + 숫자 8자리 구조 검증 | default 대상 |
| `VN_TIN` | 베트남 세금번호/납세자번호 | regex | 10자리 또는 10자리+3자리 branch suffix | default 대상, 앞쪽 라벨 중심 |
| `VN_SI` | 베트남 사회보험/건강보험 코드 | regex | 10자리 구조 검증 | default 대상, 앞쪽 라벨 중심 |

외국인등록번호(`FN`)는 주민등록번호(`SN`)와 동일한 후보 스캔 결과에서 분기한다. 뒤 7자리 첫 숫자가 `5`, `6`, `7`, `8`이면 `FN`으로 반환하고, `1`, `2`, `3`, `4`는 `SN`으로 반환한다. 베트남 전용 타입의 문맥 라벨은 베트남어 성조 포함/미포함 표현, 영문 표현, 한국어 운영 표현을 포함한다. `VN_TIN`, `VN_SI`는 일반 10자리 숫자와 충돌 가능성이 높아 문맥 hybrid 설정에서 `label_direction: before`와 짧은 `label_window`를 사용한다.

## 6. 룰셋 설계

### 6.1 룰셋 파일

| 파일 | 설명 |
| --- | --- |
| `app/rules/_ruleset.yaml` | default 룰셋 |
| `app/rules/_ruleset_strict.yaml` | strict 룰셋 |
| `app/rules/sn.yaml` | 주민등록번호 룰 |
| `app/rules/ssn.yaml` | SSN 룰 |
| `app/rules/dn.yaml` | 운전면허번호 룰 |
| `app/rules/pn.yaml` | 여권번호 룰 |
| `app/rules/mn.yaml` | 전화번호 룰 |
| `app/rules/brn.yaml` | 사업자등록번호 룰 |
| `app/rules/bn.yaml` | 계좌번호 룰 |
| `app/rules/bn_strict.yaml` | strict 계좌번호 룰 |
| `app/rules/an.yaml` | 주소 룰 |
| `app/rules/cn.yaml` | 카드번호 룰 |
| `app/rules/eml.yaml` | 이메일 룰 |
| `app/rules/vn_cccd.yaml` | 베트남 시민신분증/개인식별번호 룰 |
| `app/rules/vn_mn.yaml` | 베트남 휴대폰번호 룰 |
| `app/rules/vn_pn.yaml` | 베트남 여권번호 룰 |
| `app/rules/vn_tin.yaml` | 베트남 세금번호/납세자번호 룰 |
| `app/rules/vn_si.yaml` | 베트남 사회보험/건강보험 코드 룰 |
| `app/rules/context.yaml` | 문맥 필터 설정 |

### 6.2 룰셋 전환

HTTP에서는 `X-PII-RULESET` header를 사용한다. gRPC에서는 `DetectRequest.ruleset` 필드를 사용한다.

### 6.3 룰셋 메타

응답 `meta`에는 다음 값이 포함된다.

- `ruleset_name`
- `ruleset_version`
- `ruleset_updated_at`

## 7. 문맥 필터 설계

### 7.1 목적

문맥 필터는 정규식 또는 Hyperscan으로 탐지된 후보 중 실제 개인정보일 가능성이 낮은 항목을 제거하기 위한 후처리 단계이다.

### 7.2 동작 방식

`default` 룰셋은 `post_context` 단계를 포함한다. 현재 설정은 embedding 기반 semantic filtering이다.

주요 설정:

| 항목 | 값 |
| --- | --- |
| 활성화 | `enabled: true` |
| 방식 | `method: embed` |
| 모델 | `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` |
| 기본 threshold | `0.55` |
| context window | 주변 문장 2개 |
| target keys | `SN`, `FN`, `SSN`, `DN`, `PN`, `BRN`, `BN`, `CN`, `VN_CCCD`, `VN_MN`, `VN_PN`, `VN_TIN`, `VN_SI` |

### 7.3 Hybrid scoring

문맥 필터는 semantic score 외에 다음 힌트를 조합한다.

- label pattern
- table header hint
- 반복 출현 boost
- digit ratio
- 타입별 threshold
- force pass phrase
- non-PII phrase

### 7.4 Debug

`POST /debug/context` API를 통해 문맥 필터의 score 및 통과/거절 근거를 확인할 수 있다.

## 8. 긴 텍스트 처리 설계

### 8.1 Split 처리

입력 길이가 `PII_SPLIT_TEXT_LEN` 이상이면 chunk로 분할한다. chunk 간 경계 누락을 줄이기 위해 overlap을 적용한다.

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `PII_SPLIT_ENABLED` | `true` | split 사용 여부 |
| `PII_SPLIT_TEXT_LEN` | `50000` | split 시작 길이 |
| `PII_SPLIT_CHUNK_CHARS` | `50000` | chunk 크기 |
| `PII_SPLIT_OVERLAP_CHARS` | `2000` | overlap 크기 |
| `PII_SPLIT_MAX_WORKERS` | `1` | worker 수 |
| `PII_SPLIT_MAX_CHUNKS` | `64` | 최대 chunk 수 |

### 8.2 Merge 처리

chunk 결과는 원문 offset 기준으로 보정되며, `(start, end, matchString)` 기준으로 dedup 처리된다.

### 8.3 긴 입력 관측 모드

긴 입력에서도 짧은 입력과 같은 detector 및 문맥 정책을 적용한다. `FASTPATH` 호환 변수는
로그와 성능 측정에서 긴 입력 여부를 표시할 뿐 탐지 타입이나 결과 수를 줄이지 않는다.

| 변수 | 기본값 |
| --- | --- |
| `PII_FASTPATH_ENABLED` | `true` |
| `PII_FASTPATH_TEXT_LEN` | `50000` |

## 9. 파일 탐지 설계

`POST /pii/detect/file`은 파일 업로드를 받아 임시 파일로 저장한 뒤 `xutf_8` 바이너리로 텍스트를 추출한다. 추출된 텍스트는 일반 `/pii/detect`와 동일한 탐지 엔진으로 처리된다.

처리 흐름:

```text
파일 업로드
  -> 임시 파일 저장
  -> xutf_8 실행
  -> UTF-8 텍스트 획득
  -> PII 탐지
  -> 임시 파일 삭제
  -> 결과 반환
```

관련 환경 변수:

| 변수 | 기본값 |
| --- | --- |
| `XUTF8_BINARY_PATH` | `/app/bin/xutf_8` |
| `XUTF8_TIMEOUT_SEC` | `60` |

## 10. 배포 설계

### 10.1 HTTP 배포

| 항목 | 값 |
| --- | --- |
| Dockerfile | `Dockerfile.http` |
| Compose | `docker-compose.yml` |
| Service | `api` |
| Host port | `8005` |
| Container port | `8000` |

### 10.2 HTTP CPU 배포

| 항목 | 값 |
| --- | --- |
| Compose | `docker-compose.http-cpu.yml` |
| Start script | `scripts/start_http_cpu.sh` |
| Stop script | `scripts/stop_http_cpu.sh` |

특징:

- `PII_EMBED_DEVICE=cpu`

### 10.3 HTTPS 배포

| 항목 | 값 |
| --- | --- |
| Compose | `docker-compose.https.yml` |
| HTTPS-only override | `docker-compose.https-only.yml` |
| HTTP scale override | `docker-compose.http-scale.yml` |
| Service | `https-proxy` |
| Proxy image | `nginx:1.27-alpine` |
| Default port | `28443` |
| Certificate | `certs/tls.crt` |
| Private key | `certs/tls.key` |

실행 스크립트:

- `scripts/start_http_https.sh`
- `scripts/stop_http_https.sh`
- `scripts/start_http_https_only.sh`
- `scripts/stop_http_https_only.sh`
- `scripts/start_http_cpu_https.sh`
- `scripts/stop_http_cpu_https.sh`
- `scripts/start_http_cpu_https_only.sh`
- `scripts/stop_http_cpu_https_only.sh`
- `scripts/start_http_cpu_https_only_scale_3.sh`
- `scripts/stop_http_cpu_https_only_scale.sh`

### 11.4 gRPC 배포

| 모드 | 구성 | 포트 |
| --- | --- | --- |
| direct | 단일 `api-grpc` | `50051` |
| HAProxy LB | `api-grpc` 3 replica + `api-grpc-lb` | `50055` |

관련 스크립트:

- `start_grpc_direct.sh`
- `start_grpc_lb_3.sh`

## 12. 운영 설계

### 12.1 주요 명령

HTTP CPU 실행:

```bash
./scripts/start_http_cpu.sh
```

HTTP HTTPS 실행:

```bash
./scripts/start_http_https.sh
```

HTTP HTTPS 전용 실행:

```bash
./scripts/start_http_https_only.sh
```

HTTP CPU HTTPS 실행:

```bash
./scripts/start_http_cpu_https.sh
```

HTTP CPU HTTPS 전용 실행:

```bash
./scripts/start_http_cpu_https_only.sh
```

HTTP CPU HTTPS 전용 3개 수평확장 실행:

```bash
PII_HTTP_SCALE=3 ./scripts/start_http_cpu_https_only_scale_3.sh
```

이 모드는 `docker-compose.http-scale.yml`로 `api`의 고정 컨테이너명과 HTTP host port publish를 제거한다. Nginx HTTPS proxy는 Docker DNS resolver로 `api:8000`을 동적으로 재해석하고 upstream 장애 시 다른 replica로 재시도한다.

gRPC LB 실행:

```bash
./scripts/start_grpc_lb_3.sh 6
```

### 12.2 로그

로그는 `/logs`에 기록되며 compose에서는 `./logs:/logs`로 마운트된다.

주요 로그 항목:

- 요청 ID
- 입력 chars/bytes
- 룰셋
- 탐지 소요 시간
- stage별 소요 시간
- 타입별 kept count
- gRPC worker 및 stream 설정

### 12.3 모니터링 포인트

- API 응답 상태
- 탐지 latency
- 타입별 탐지 건수
- stage별 slow log
- 컨테이너 상태
- CPU 사용률
- gRPC throughput
- Nginx HTTPS proxy 상태

## 13. 성능 설계

### 13.1 고속 탐지

Hyperscan을 우선 사용하고, 지원하지 않는 패턴은 Python regex로 fallback한다. combined Hyperscan DB를 사용하면 여러 타입의 scan을 공유하여 중복 scan 비용을 줄인다.

### 13.2 긴 텍스트 성능

긴 텍스트는 split으로 처리하되 전체 입력과 전체 detector 범위를 유지한다.

- split으로 chunk 단위 처리
- overlap으로 경계 누락 완화
- 설정된 chunk 수를 넘으면 chunk 크기를 자동 확장하여 원문 끝까지 처리
- 요청의 타입별 결과 수 제한을 최종 병합 결과에 동일하게 적용

### 13.3 gRPC 성능

gRPC는 탐지 process 수와 replica 수를 조정할 수 있다. 운영 기본값은 인스턴스당 탐지
process `4`, 대기 큐 `1`, replica `3`이며 총 12건을 동시에 탐지하고 최대 3건을
대기시킨다. 큐 포화 요청은 gRPC `RESOURCE_EXHAUSTED`로 즉시 거절한다.
HAProxy는 `leastconn`, HTTP/2 backend connection reuse, Docker DNS
`server-template`을 사용해 단일 장기 gRPC 채널의 RPC도 세 backend로 분산한다.
`scripts/grpc_benchmark.py`로 gRPC throughput, p50, p95, p99 latency를 측정한다.
`scripts/protocol_benchmark.py`는 동일 입력과 영속 연결로 HTTP, 단일 gRPC, LB gRPC를 비교하고
응답의 끝부분 BRN 탐지 결과까지 검증한다. 단일 요청 latency와 동시 처리 throughput은 별도로
판단한다.

## 14. 보안 설계

### 14.1 전송 구간 보호

HTTPS는 Nginx proxy에서 TLS를 종료한다. 인증서는 `certs/tls.crt`, `certs/tls.key`로 마운트한다.

### 14.2 인증

현재 HTTP/gRPC API 자체 인증은 구현되어 있지 않다. 외부 공개 시 다음 중 하나 이상의 외부 보안 계층이 필요하다.

- API Gateway 인증
- Ingress 인증
- WAF
- mTLS
- 사설망 제한
- IP allowlist

### 14.3 비밀 정보 관리

TLS private key가 저장소에 포함되지 않도록 `certs/`는 `.gitignore`에 등록되어 있다.

## 15. 제약사항

- 공개 API 자체 인증은 제공하지 않는다.
- gRPC TLS는 현재 설계 범위에 포함되지 않는다.
- 문맥 필터는 embedding 모델 성능과 threshold 설정에 영향을 받는다.
- 매우 긴 문서는 chunk 크기가 커질 수 있어 입력 길이와 후보 수에 따라 지연시간이 증가할 수 있다.
- 파일 탐지는 `xutf_8` 추출 성공 여부에 의존한다.
- semantic embedding은 CPU에서 동작하므로 입력 길이와 후보 수에 따라 latency가 증가할 수 있다.

## 16. 향후 개선사항

- HTTP/gRPC 공통 인증 계층 추가
- gRPC TLS 또는 mTLS 지원
- OpenAPI/Proto 기반 SDK 생성
- 룰셋 관리 UI 추가
- 탐지 결과 검수 및 피드백 데이터 관리
- 문맥 필터 threshold 운영 관리 기능
- Prometheus metrics endpoint 추가
- structured audit log 추가
- 운영 인증서 자동 갱신 연동

## 17. 부록

### 17.1 주요 환경 변수

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `PII_RULESET` | `default` | 기본 룰셋 |
| `PII_MODEL_PRELOAD_ENABLED` | `true` | 모델 preload |
| `PII_EMBED_DEVICE` | `cpu` | 임베딩 장치. CPU 전용으로 고정 |
| `PII_HS_COMBINED_ENABLED` | `true` | combined Hyperscan |
| `PII_CONTEXT_EMBED_MAX_CHARS` | `256` | context embedding 최대 길이 |
| `PII_SPLIT_ENABLED` | `true` | 긴 텍스트 split |
| `PII_FASTPATH_ENABLED` | `true` | 긴 입력 관측 로그(호환 변수) |
| `PII_GRPC_MAX_WORKERS` | `7` | gRPC handler thread 수 |
| `PII_DETECT_PROCESS_WORKERS` | `4` | 인스턴스별 실제 탐지 process 수 |
| `PII_DETECT_QUEUE_LIMIT` | `1` | 인스턴스별 탐지 대기 한도 (`1` 또는 `2`) |
| `PII_HTTPS_PORT` | `28443` | HTTPS 외부 포트 |
| `PII_LOG_LEVEL` | `INFO` | 로그 레벨 |

### 17.2 산출물 파일

| 파일 | 설명 |
| --- | --- |
| `docs/DESIGN_INPUT.md` | 설계서 작성 입력 자료 |
| `docs/DESIGN_SPEC.md` | 설계서 Markdown 원본 |
| `docs/DESIGN_SPEC.docx` | 설계서 DOCX 산출물 |
