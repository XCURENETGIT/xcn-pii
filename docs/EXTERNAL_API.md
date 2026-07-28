# xcn-pii External API

이 문서는 외부 연동용 공개 API 기준 문서다. 내부 디버그 API나 운영용 구현 세부사항은 제외한다.

## Overview

- 목적: 텍스트에서 개인정보(PII) 후보를 탐지
- 지원 인터페이스:
  - HTTP/JSON
  - gRPC
- 주요 탐지 타입:
  - `SN`
  - `FN`
  - `SSN`
  - `DN`
  - `PN`
  - `MN`
  - `BRN`
  - `BN`
  - `AN`
  - `CN`
  - `EML`
  - `VN_CCCD`
  - `VN_MN`
  - `VN_PN`
  - `VN_TIN`
  - `VN_SI`

탐지 타입 요약:

| 타입 | 의미 | 대표 형식 |
| --- | --- | --- |
| `SN` | 한국 주민등록번호 | `900101-1234567` |
| `FN` | 외국인등록번호 | `900101-5123450` |
| `SSN` | 미국 Social Security Number | `123-45-6789` |
| `DN` | 운전면허번호 | `11-22-333333-44` |
| `PN` | 여권번호 | `M12345678` |
| `MN` | 전화번호/휴대폰번호 | `010-1234-5678` |
| `BRN` | 사업자등록번호 | `123-45-67890` |
| `BN` | 계좌번호/은행 관련 번호 | 은행명 또는 계좌 라벨 주변 숫자 |
| `AN` | 주소 | `서울시 은평구 가좌로 276` |
| `CN` | 카드번호 | `4111-1111-1111-1111` |
| `EML` | 이메일 | `test@example.com` |
| `VN_CCCD` | 베트남 시민신분증/개인식별번호 | `001234567890` |
| `VN_MN` | 베트남 휴대폰번호 | `098-123-4567` |
| `VN_PN` | 베트남 여권번호 | `B12345678` |
| `VN_TIN` | 베트남 세금번호/납세자번호 | `0312345678`, `0312345678-001` |
| `VN_SI` | 베트남 사회보험/건강보험 코드 | `0123456789` |

## Base Endpoints

- HTTP:
  - 기본 예시: `http://<host>:8005`
- gRPC direct:
  - 기본 예시: `<host>:50051`
- gRPC LB:
  - 기본 예시: `<host>:50055`

실제 포트는 배포 환경에 따라 달라질 수 있다.

## Authentication

현재 공개 HTTP/gRPC API 레벨에서 별도 인증 헤더는 강제하지 않는다.

외부 공개 시에는 반드시 다음 중 하나를 권장한다.

- API Gateway 인증
- Ingress/WAF 인증
- mTLS 또는 사설망 제한

## HTTP API

### 1. Detect PII

- Method: `POST`
- Path: `/pii/detect`
- Content-Type: `application/json`

Request body:

```json
{
  "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
  "max_results_per_type": 100
}
```

Headers:

- `X-PII-RULESET`: optional
  - 예: `strict`
  - 미지정 시 서버 기본 룰셋 사용

Request fields:

- `text`
  - 타입: `string`
  - 필수
  - 최소 길이: `1`
  - 최대 길이: `10000000`
- `max_results_per_type`
  - 타입: `integer`
  - 선택
  - 기본값: `500`
  - 범위: `1` ~ `5000`

Success response example:

```json
{
  "success": true,
  "status": 200,
  "data": {
    "SN_CNT": 1,
    "SN": [
      {
        "start": 10,
        "end": 24,
        "matchString": "900101-1234567",
        "isValid": true,
        "context_score": 1.0,
        "context_score_norm": 0.91,
        "context_hybrid_score": 0.91,
        "context_method": "embed",
        "context_accept_by": "embed",
        "context_pass": true,
        "detected_by": "regex"
      }
    ],
    "EML_CNT": 1,
    "EML": [
      {
        "start": 31,
        "end": 47,
        "matchString": "test@example.com",
        "detected_by": "regex"
      }
    ],
    "CN_CNT": 1,
    "CN": [
      {
        "start": 55,
        "end": 74,
        "matchString": "4111-1111-1111-1111",
        "isValid": true,
        "detected_by": "regex"
      }
    ]
  },
  "meta": {
    "ruleset_name": "default",
    "ruleset_version": "2026-03-01",
    "ruleset_updated_at": "2026-03-01T12:00:00"
  }
}
```

Response fields:

- `success`
  - 처리 성공 여부
- `status`
  - 응답 상태 코드
- `data`
  - 타입별 탐지 결과
- `meta`
  - 적용된 룰셋 정보

`data` object rules:

- 탐지 결과가 없는 타입은 응답에서 생략될 수 있다.
- 각 타입은 `*_CNT` 와 배열 필드 쌍으로 반환된다.
- 배열 항목은 `MatchItem` 구조를 따른다.

Supported `MatchItem` fields:

- `start`: 시작 offset
- `end`: 종료 offset
- `matchString`: 원문 매치 문자열
- `isValid`: 형식 검증 결과가 있는 경우
- `context_score`
- `context_score_norm`
- `context_hybrid_score`
- `context_method`
- `context_accept_by`
- `context_pass`
- `detected_by`

Typical error cases:

- `422 Unprocessable Entity`
  - 필수 필드 누락
  - `text` 길이 제한 위반
  - `max_results_per_type` 범위 위반
- `500 Internal Server Error`
  - 서버 내부 처리 오류

curl example:

```bash
curl -X POST "http://<host>:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: default" \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
    "max_results_per_type": 100
  }'
```

### 2. List Rulesets

- Method: `GET`
- Path: `/pii/rulesets`

Success response example:

```json
{
  "rules_dir": "app/rules",
  "rulesets": [
    {
      "ruleset_name": "default",
      "ruleset_version": "2026-03-01",
      "ruleset_updated_at": "2026-03-01T12:00:00",
      "ruleset_path": "app/rules/_ruleset.yaml"
    },
    {
      "ruleset_name": "strict",
      "ruleset_version": "2026-03-05",
      "ruleset_updated_at": "2026-03-05T09:00:00",
      "ruleset_path": "app/rules/_ruleset_strict.yaml"
    }
  ]
}
```

용도:

- 서버가 제공하는 룰셋 이름 확인
- 연동 측에서 `X-PII-RULESET` 또는 gRPC `ruleset` 필드에 넣을 값 조회

### 3. Replace PII Exclusions

- Method: `PUT`
- Path: `/pii/exclusions`
- Content-Type:
  - `application/json`
  - 또는 `multipart/form-data`의 `file` 필드로 `.json` 파일 업로드

용도:

- 외부 시스템에서 이미 매핑/식별된 값은 PII 탐지 결과에서 제외하도록 예외 목록을 등록/교체한다.
- 업로드가 성공하면 이후 `/pii/detect`, `/pii/detect/file`, gRPC `Detect` 결과에 즉시 적용된다.
- 전체 예외 목록을 교체하는 idempotent API이므로 `PUT`을 사용한다.

Supported JSON shapes:

```json
{
  "values": ["test@example.com"],
  "types": {
    "SN": ["900101-1234567"],
    "MN": ["010-1234-5678"]
  },
  "entries": [
    {"type": "CN", "value": "4111-1111-1111-1111"}
  ]
}
```

Notes:

- `values`: 모든 PII 타입에 공통 적용되는 예외 값
- `types`: 타입별 예외 값
- `entries`: `{ "type": "<PII_TYPE>", "value": "<EXCLUDED_VALUE>" }` 배열
- 타입 키를 최상위에 직접 둘 수도 있다. 예: `{ "SN": ["900101-1234567"] }`
- 외국인등록번호는 `SN`이 아니라 `FN` 타입으로 예외처리한다.
- 베트남 전용 타입도 예외처리 가능하다. 예: `VN_CCCD`, `VN_MN`, `VN_PN`, `VN_TIN`, `VN_SI`
- 비교 시 대소문자, 공백, 주요 구분자(`-`, `.`, `_`, `@`, `:`, `/`, `\`) 차이는 정규화된다.
- 예외 값에 `*`가 포함되면 wildcard 패턴으로 처리한다.
  - `*1234`: 정규화된 탐지값이 `1234`로 끝나면 제외
  - `900101*`: 정규화된 탐지값이 `900101`로 시작하면 제외
  - `*101123*`: 정규화된 탐지값에 `101123`이 포함되면 제외
- 예외 값에 `*`가 없으면 정규화 후 전체 값이 일치하는 경우에만 제외한다.
- 저장 경로는 `PII_DETECTION_EXCLUSION_FILE` 환경변수로 변경할 수 있으며 기본값은 `data/pii_detection_exclusions.json`이다.

Success response example:

```json
{
  "success": true,
  "status": 200,
  "path": "data/pii_detection_exclusions.json",
  "updated_at": "2026-06-15T13:20:00+0900",
  "total_values": 4,
  "type_counts": {
    "CN": 1,
    "MN": 1,
    "SN": 1
  }
}
```

curl examples:

```bash
curl -X PUT "http://<host>:8005/pii/exclusions" \
  -H "Content-Type: application/json" \
  -d '{
    "types": {
      "SN": ["900101-1234567"],
      "EML": ["test@example.com"]
    }
  }'
```

```bash
curl -X PUT "http://<host>:8005/pii/exclusions" \
  -F "file=@pii_detection_exclusions.json;type=application/json"
```

## gRPC API

Proto:

- [`app/proto/pii.proto`](/C:/xcn_prj/xcn-pii/app/proto/pii.proto)

Service:

- `xcn.pii.v1.PiiDetector`

RPC methods:

- `Health(HealthRequest) returns (HealthResponse)`
- `Detect(DetectRequest) returns (DetectResponse)`
- `ReplaceExclusions(ReplaceExclusionsRequest) returns (ReplaceExclusionsResponse)`

### 1. Health

Request:

```proto
message HealthRequest {}
```

Response:

```proto
message HealthResponse {
  bool ok = 1;
  string service = 2;
  string version = 3;
}
```

### 2. Detect

Request:

```proto
message DetectRequest {
  string text = 1;
  int32 max_results_per_type = 2;
  string ruleset = 3;
}
```

Field notes:

- `text`
  - 필수
- `max_results_per_type`
  - 선택
  - 일반 권장값: `100` ~ `500`
- `ruleset`
  - 선택
  - 예: `default`, `strict`

Response:

```proto
message DetectResponse {
  bool success = 1;
  int32 status = 2;
  string message = 3;
  PiiData data = 4;
  PiiMeta meta = 5;
}
```

`PiiData`에는 HTTP 응답과 동일한 타입의 count/list 필드가 포함된다. gRPC 필드명은 proto 관례에 따라 소문자 snake_case를 사용한다.

| HTTP 필드 | gRPC 필드 |
| --- | --- |
| `FN_CNT`, `FN` | `fn_cnt`, `fn` |
| `VN_CCCD_CNT`, `VN_CCCD` | `vn_cccd_cnt`, `vn_cccd` |
| `VN_MN_CNT`, `VN_MN` | `vn_mn_cnt`, `vn_mn` |
| `VN_PN_CNT`, `VN_PN` | `vn_pn_cnt`, `vn_pn` |
| `VN_TIN_CNT`, `VN_TIN` | `vn_tin_cnt`, `vn_tin` |
| `VN_SI_CNT`, `VN_SI` | `vn_si_cnt`, `vn_si` |

gRPC example with `grpcurl`:

```bash
grpcurl -plaintext \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567 입니다.",
    "max_results_per_type": 100,
    "ruleset": "default"
  }' \
  <host>:50051 xcn.pii.v1.PiiDetector/Detect
```

LB endpoint example:

```bash
grpcurl -plaintext \
  -d '{
    "text": "연락처는 010-1234-5678 입니다.",
    "max_results_per_type": 100
  }' \
  <host>:50055 xcn.pii.v1.PiiDetector/Detect
```

### 3. Replace Exclusions

HTTP `PUT /pii/exclusions`와 동일하게 탐지 예외 목록 전체를 교체한다.

Request:

```proto
message ReplaceExclusionsRequest {
  string json_payload = 1;
}
```

`json_payload`에는 HTTP API에서 사용하는 예외 JSON을 문자열로 넣는다.

Response:

```proto
message ReplaceExclusionsResponse {
  bool success = 1;
  int32 status = 2;
  string message = 3;
  string path = 4;
  string updated_at = 5;
  int32 total_values = 6;
  map<string, int32> type_counts = 7;
}
```

grpcurl example:

```bash
grpcurl -plaintext \
  -d '{
    "json_payload": "{\"types\":{\"SN\":[\"900101-1234567\"],\"EML\":[\"test@example.com\"]}}"
  }' \
  <host>:50055 xcn.pii.v1.PiiDetector/ReplaceExclusions
```

Vietnam PII example:

```bash
grpcurl -plaintext \
  -d '{
    "text": "CCCD: 001234567890, so dien thoai 098-123-4567, ho chieu B12345678, ma so thue 0312345678-001, ma so BHXH 0123456789",
    "max_results_per_type": 100,
    "ruleset": "default"
  }' \
  <host>:50055 xcn.pii.v1.PiiDetector/Detect
```

## Result Semantics

- `start`, `end`는 원문 문자열 기준 offset이다.
- 동일 타입에서 여러 결과가 반환될 수 있다.
- 결과는 문맥 점수나 후처리 결과에 따라 최종 유지된 항목만 반환된다.
- `CN`은 HTTP/JSON과 gRPC 응답 모두에서 제공된다.
- 베트남 전용 타입은 `VN_CCCD`(시민신분증), `VN_MN`(휴대폰 번호), `VN_PN`(여권번호), `VN_TIN`(세금번호), `VN_SI`(사회보험/건강보험 코드)로 반환된다.
- `VN_TIN`, `VN_SI`는 10자리 숫자 형식이 다른 업무 번호와 충돌하기 쉬우므로 문맥 라벨이 후보 앞쪽에 있는 경우를 중심으로 통과시킨다.

## Recommended Client Handling

- 입력 원문은 UTF-8 기준으로 전송
- 매우 긴 텍스트는 애플리케이션 레벨에서 분할 전송을 권장
- `status=200`, `success=true` 여부를 함께 확인
- 결과 배열이 없거나 필드가 누락된 경우 "해당 타입 결과 없음"으로 처리
- gRPC `RESOURCE_EXHAUSTED`는 서버 처리/대기 용량이 모두 사용 중이라는 의미다.
  즉시 재시도하지 말고 backoff 후 재시도한다. 애플리케이션 큐에서 거절된 경우
  trailing metadata의 `x-pii-error-code=PII_QUEUE_FULL`과 `retry-after-ms`를 함께 확인할 수 있다.

## Operational Notes

- 응답 시간은 텍스트 길이, 룰셋, 문맥 필터 사용 여부에 따라 달라질 수 있다.
- 초기 기동 직후에는 모델 preload 상태에 따라 첫 요청이 느릴 수 있다.
- 외부 공개 시 요청 크기 제한, rate limiting, 인증 계층을 별도로 두는 것을 권장한다.

## Change Management

외부 연동 안정성을 위해 다음 항목이 바뀌면 버전 공지 대상이다.

- 엔드포인트 경로 변경
- 요청/응답 필드명 변경
- 기본 룰셋 동작 변경
- 포트 또는 공개 프로토콜 변경
