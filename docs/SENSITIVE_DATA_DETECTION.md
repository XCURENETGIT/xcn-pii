# 기밀정보 탐지 기능

## 목적

기존 개인정보 탐지 기능과 별도로 요청 본문에 포함된 OTP, API Key, 인증 토큰, 비밀번호, 내부 접속정보를 탐지한다. 이 기능은 `feature/secret-detection` 브랜치에서 개발하며 기존 `main` 제품 유지보수 작업과 분리한다.

## 탐지 타입

| 반환 타입 | 탐지 대상 | 기본 판단 기준 |
| --- | --- | --- |
| `OTP` | OTP, 인증번호, verification code | 관련 라벨 주변의 4~8자리 숫자 |
| `API_KEY` | AWS, GitHub, Google, Slack, OpenAI, Stripe 키와 일반 API 키 | 알려진 공급자 형식 또는 명시적인 키 라벨 + 길이/엔트로피 조건 |
| `AUTH_TOKEN` | JWT, Bearer, Basic, access/refresh/auth token | 토큰 구조 또는 인증 헤더/라벨 |
| `PASSWORD` | 비밀번호, password, passwd, pwd, passphrase | 명시적인 라벨에 할당된 따옴표/비따옴표 값 |
| `INTERNAL_ACCESS` | 사설 IP, 내부 호스트, 내부 접속 URL | 사설·loopback·link-local IP 또는 내부용 호스트 구조 |

예시:

```text
인증번호: 482913
API_KEY=abcDEF1234567890xyz
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123
비밀번호: S3cure!Pass#2026
내부 URL: postgresql://svc:secret@db01.internal:5432/app
```

탐지 결과는 기존 HTTP 응답의 `data`에 `OTP_CNT`/`OTP`, `API_KEY_CNT`/`API_KEY`, `AUTH_TOKEN_CNT`/`AUTH_TOKEN`, `PASSWORD_CNT`/`PASSWORD`, `INTERNAL_ACCESS_CNT`/`INTERNAL_ACCESS` 쌍으로 추가된다. gRPC에서는 동일 항목을 소문자 snake_case로 반환한다.

## 오탐 방지 기준

- OTP는 라벨 없는 일반 4~8자리 숫자를 탐지하지 않는다.
- 일반 API Key는 명시적인 키 라벨이 있어야 하며 최소 길이, Shannon entropy, 문자 종류 조건을 함께 검사한다.
- 비밀번호는 문장 안의 일반적인 `password` 단어가 아니라 값 할당 형식만 탐지한다.
- `INTERNAL_ACCESS`는 공인 IP와 외부 공개 URL을 제외한다.
- 내부 호스트는 단일 호스트명, `localhost`, 사설 IP 또는 `.internal`, `.local`, `.lan`, `.corp`, `.intranet`, `.svc` 계열을 허용한다.

## 규칙 관리

규칙 파일은 다음 위치에 있다.

- `app/rules/otp.yaml`
- `app/rules/api_key.yaml`
- `app/rules/auth_token.yaml`
- `app/rules/password.yaml`
- `app/rules/internal_access.yaml`

각 정규식은 가능하면 실제 기밀 값만 `(?P<value>...)` 그룹으로 캡처해야 한다. 다음 선택 조건을 규칙별로 사용할 수 있다.

- `min_length`, `max_length`
- `min_entropy`
- `min_character_classes`
- `validator`: `private_ip`, `internal_host`, `internal_url`
- `trim_trailing`

규칙을 바꾼 뒤에는 최소한 다음 테스트를 실행한다.

```powershell
python -m pytest -q app/test_sensitive_detection.py app/test_sensitive_redaction.py
```

## 요청 원문 로그 보호

`PII_LOG_REQUEST_TEXT_ENABLED=true`로 요청 본문 로그를 활성화한 경우, 새 기밀정보 타입은 기본적으로 로그에 원문 대신 `[REDACTED:<TYPE>]`으로 기록된다.

```dotenv
PII_LOG_REQUEST_TEXT_REDACT_SENSITIVE=true
```

마스킹 중 오류가 발생하면 요청 원문을 남기지 않고 `[REDACTION_FAILED]`만 기록하는 fail-closed 방식이다. 운영에서는 `PII_LOG_REQUEST_TEXT_REDACT_SENSITIVE=false`를 사용하지 않는 것을 권장한다. 이 마스킹은 새 기밀정보 타입을 대상으로 하며, 모든 개인정보 타입의 비식별화를 보장하는 범용 로그 마스커는 아니다.

## 호환성

기존 탐지 타입과 필드는 변경하지 않는다. HTTP/gRPC 응답 필드는 추가 방식이며, 신규 타입을 인식하지 않는 연동 클라이언트는 미지의 필드를 무시할 수 있어야 한다. gRPC 정적 클라이언트가 신규 필드를 사용하려면 갱신된 `pii.proto`로 코드를 다시 생성해야 한다.
