# 기밀정보 탐지 서버 검증 계획

## 검증 범위

`scripts/verify_sensitive_detection.py`는 아래 조합을 모두 실행한다.

- 인터페이스: HTTP, gRPC
- 룰셋: `default`, `strict`
- 신규 타입: `OTP`, `API_KEY`, `AUTH_TOKEN`, `PASSWORD`, `INTERNAL_ACCESS`
- 기존 회귀: `MN`

현재 테스트케이스는 양성 18개, 기존 기능 회귀 1개, 음성 11개로 구성된다. 전체 실행 건수는 `30 cases × 2 protocols × 2 rulesets = 120`건이다.

## 판정 기준

- 양성 케이스는 기대한 타입과 `matchString`이 응답에 존재해야 한다.
- `start`/`end` offset으로 원문을 잘랐을 때 `matchString`과 정확히 같아야 한다.
- `*_CNT` 값은 실제 배열 길이와 같아야 한다.
- 음성 케이스는 지정한 타입의 결과가 없어야 한다.
- 한 건이라도 조건을 만족하지 않거나 호출 오류가 발생하면 프로세스 종료 코드는 `1`이다.
- 전체 결과는 JSON 파일로 저장하여 케이스별 실제 탐지값과 실패 원인을 확인한다.

## 주요 케이스

| 구분 | 케이스 | 기대 결과 |
| --- | --- | --- |
| 양성 | 한국어/영문 OTP, 4자리·8자리 경계 | `OTP` 탐지 |
| 양성 | AWS/GitHub/일반 고엔트로피 키 | `API_KEY` 탐지 |
| 양성 | Bearer/JWT/refresh/Basic token | `AUTH_TOKEN` 탐지 |
| 양성 | 한국어 및 따옴표 비밀번호 | `PASSWORD` 탐지 |
| 양성 | 사설 IPv4, loopback IPv6, 내부 URL, 내부 호스트 | `INTERNAL_ACCESS` 탐지 |
| 혼합 | 신규 5개 타입을 한 요청에 입력 | 모든 타입 동시 탐지 |
| 회귀 | `연락처: 010-1234-5678` | 기존 `MN` 탐지 |
| 음성 | 라벨 없는 숫자, 3자리·9자리 OTP | `OTP` 미탐지 |
| 음성 | 저엔트로피 또는 라벨 없는 일반 키 | `API_KEY` 미탐지 |
| 음성 | 정책 설명 문장의 password | `PASSWORD` 미탐지 |
| 음성 | 공인 IPv4/IPv6와 외부 URL | `INTERNAL_ACCESS` 미탐지 |
| 음성 | 짧은 Bearer 값, 유효하지 않은 IPv4 | 해당 타입 미탐지 |

## 52번 서버 격리 설치 기준

테스트 설치는 `/data01/xcn-pii-secret-detection`에서 수행한다. 기존 `/data01/xcn-pii` 컨테이너와 포트를 유지하기 위해 다음 별도 포트를 사용한다.

| 서비스 | 테스트 포트 |
| --- | ---: |
| HTTP | `18005` |
| gRPC direct | `150051` |

기동 예시:

```bash
cd /data01/xcn-pii-secret-detection
PII_IMAGE_TAG=<feature-image-tag> docker compose -f docker-compose.sensitive-test.yml up -d
```

검증 실행 예시:

```bash
docker run --rm --network host \
  -v "$PWD/scripts/verify_sensitive_detection.py:/tests/verify_sensitive_detection.py:ro" \
  -v "$PWD/test-results:/results" \
  "xcn-pii/api-http-cpu:<feature-image-tag>" \
  python /tests/verify_sensitive_detection.py \
    --protocol both \
    --rulesets default,strict \
    --output /results/sensitive-detection-report.json
```

## 요청 로그 마스킹 검증

테스트 Compose는 요청 원문 로깅과 기밀정보 마스킹을 활성화한다. 고유 마커를 포함한 요청을 전송한 뒤 다음을 확인한다.

- 로그에 고유 마커가 존재한다.
- 실제 OTP/API Key/토큰/비밀번호/내부 IP 값은 존재하지 않는다.
- `[REDACTED:OTP]`, `[REDACTED:API_KEY]`, `[REDACTED:AUTH_TOKEN]`, `[REDACTED:PASSWORD]`, `[REDACTED:INTERNAL_ACCESS]`가 존재한다.
- `sensitive_redaction=applied` 상태가 기록된다.
