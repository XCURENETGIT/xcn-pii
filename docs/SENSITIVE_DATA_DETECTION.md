# 기밀정보 탐지 기능

## 목적

기존 개인정보 탐지 기능과 별도로 요청 본문에 포함된 OTP, API Key, 인증 토큰, 비밀번호, 내부 접속정보와 고위험 시크릿을 탐지한다. 이 기능은 `feature/secret-detection` 브랜치에서 개발하며 기존 `main` 제품 유지보수 작업과 분리한다.

## 탐지 타입

| 반환 타입 | 탐지 대상 | 기본 판단 기준 |
| --- | --- | --- |
| `OTP` | OTP, MFA/2FA/TOTP, 인증·확인·보안·로그인 코드 | 관련 라벨 전후의 4~8자리 숫자 |
| `API_KEY` | 공급자 전용 키와 일반 API/서비스/구독/웹훅 키 | 알려진 공급자 형식 또는 명시적인 키 라벨 + 길이/엔트로피 조건 |
| `AUTH_TOKEN` | JWT, Bearer, Basic, access/refresh/session/CSRF token | 토큰 구조 또는 인증 헤더/설정 라벨 |
| `PASSWORD` | 비밀번호, password/passwd/pwd/passphrase | JSON/YAML/XML/CLI 및 명시적인 문장 라벨에 할당된 값 |
| `INTERNAL_ACCESS` | 사설 IP/CIDR, 내부 호스트·URL·socket | 사설·loopback·link-local 네트워크 또는 내부용 구조 |
| `PRIVATE_KEY` | PEM/OpenSSH/PGP 개인키, JSON 이스케이프 개인키 | 정확한 armor header/footer 및 본문 구조 검증 |
| `CLOUD_CREDENTIAL` | AWS secret/session credential, Azure Storage account key | 공급자 고정 라벨과 길이·엔트로피 검증 |
| `CONNECTION_STRING` | 계정·비밀번호가 포함된 DB/JDBC/서비스 연결 문자열 | URL userinfo 또는 key/value 자격증명 구조 검증 |
| `SIGNED_URL` | AWS/GCS 서명 URL, Azure SAS, Slack/Discord webhook | 공급자별 hostname/path/query 조합 검증 |
| `MFA_SECRET` | HOTP/TOTP 공유 시드, `otpauth` secret | 명시 라벨 또는 URI와 Base32 구조 검증 |
| `RECOVERY_CODE` | MFA·계정 복구/백업 코드 | 명시적인 recovery/backup code 라벨 필수 |
| `SESSION_COOKIE` | 알려진 인증·세션 쿠키 값 | 제한된 쿠키명과 길이·엔트로피 검증 |

예시:

```text
인증번호: 482913
API_KEY=abcDEF1234567890xyz
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123
비밀번호: S3cure!Pass#2026
내부 URL: postgresql://svc:secret@db01.internal:5432/app
```

## 지원 문맥

- OTP: `OTP`, `TOTP`, `HOTP`, `MFA`, `2FA`, one-time password, verification/authentication/security/confirmation/login code, 인증번호, 본인확인 코드, 다단계·이중·2차 인증 코드 등
- API Key 라벨: `apiKey`, `X-API-Key`, access/secret/application/service/subscription/consumer/signing key, client/webhook secret 및 한국어 대응 표현
- API Key 공급자 형식: AWS, GitHub, GitLab, Google, Slack, OpenAI, Stripe, Hugging Face, npm, SendGrid, Twilio
- 인증토큰: Authorization/Proxy-Authorization의 Bearer·Basic·Token scheme, access/refresh/auth/session/security/OAuth/SSO/CSRF/XSRF token, JWT, session ID 및 한국어 대응 표현
- 비밀번호: JSON/YAML/환경변수 키, `password is ...`, 한국어 조사·입력 지시, `--password` CLI 인수, XML password 요소
- 내부접속정보: HTTP(S), SSH/SFTP/FTP, JDBC 및 주요 DB·Redis·AMQP·Kafka·LDAP·TCP·WebSocket URL, 사설 IPv4/IPv6/CIDR, DB/cache/broker/VPN/bastion/host/endpoint 라벨, Unix socket 경로
- 라벨이 값보다 앞서는 형식뿐 아니라 `739201 is your verification code`, `482913은 인증번호입니다`, `... is the access token/service key`와 같은 값 우선 문장도 지원한다.

탐지 결과는 기존 HTTP 응답의 `data`에 `OTP_CNT`/`OTP`, `API_KEY_CNT`/`API_KEY`, `AUTH_TOKEN_CNT`/`AUTH_TOKEN`, `PASSWORD_CNT`/`PASSWORD`, `INTERNAL_ACCESS_CNT`/`INTERNAL_ACCESS` 쌍으로 추가된다. gRPC에서는 동일 항목을 소문자 snake_case로 반환한다.

## 오탐 방지 기준

- OTP는 라벨 없는 일반 4~8자리 숫자를 탐지하지 않는다.
- 일반 API Key는 명시적인 키 라벨이 있어야 하며 최소 길이, Shannon entropy, 문자 종류 조건을 함께 검사한다.
- 비밀번호는 문장 안의 일반적인 `password` 단어가 아니라 값 할당 형식만 탐지한다.
- `INTERNAL_ACCESS`는 공인 IP와 외부 공개 URL을 제외한다.
- 내부 호스트는 명시적인 접속 라벨의 단일 호스트명, `localhost`, 사설 IP 또는 `.internal`, `.local`, `.lan`, `.corp`, `.intranet`, `.svc`, `.cluster.local`, `.home.arpa`, `.private`, `.localdomain` 계열을 허용한다.
- 공개 도메인, 공인 IPv4/IPv6/CIDR, 설명 문장, 짧거나 저엔트로피인 일반 키·토큰은 제외한다.

## 규칙 관리

규칙 파일은 다음 위치에 있다.

- `app/rules/otp.yaml`
- `app/rules/api_key.yaml`
- `app/rules/auth_token.yaml`
- `app/rules/password.yaml`
- `app/rules/internal_access.yaml`
- `app/rules/private_key.yaml`
- `app/rules/cloud_credential.yaml`
- `app/rules/connection_string.yaml`
- `app/rules/signed_url.yaml`
- `app/rules/mfa_secret.yaml`
- `app/rules/recovery_code.yaml`
- `app/rules/session_cookie.yaml`

각 정규식은 가능하면 실제 기밀 값만 `(?P<value>...)` 그룹으로 캡처해야 한다. 다음 선택 조건을 규칙별로 사용할 수 있다.

- `min_length`, `max_length`
- `min_entropy`
- `min_character_classes`
- `validator`: `private_ip`, `private_network`, `internal_host`, `internal_url`
- `flags.verbose`: 긴 문맥 정규식을 가독성 있게 여러 줄로 작성
- `prefilter_any`: 지정한 문맥 또는 공급자 prefix가 원문에 하나도 없으면 해당 정규식 실행 생략
- `trim_trailing`

1차 고위험 시크릿 규칙은 추가로 다음 성능 조건을 지킨다.

- 모든 타입과 모든 패턴에 `prefilter_any`를 둔다.
- `.*` 형태의 무제한 wildcard를 사용하지 않고 입력 길이를 정규식 자체에서도 제한한다.
- 신규 7종 전체는 `=`, `:`, `#`, PEM header가 없는 일반 문서에서 공통 syntax gate로 즉시 종료한다.
- Base64, URL query, connection credential 같은 구조 검증은 정규식 후보가 나온 경우에만 실행한다.
- detector 간 소문자 변환 결과를 요청 단위로 공유해 긴 입력을 반복 변환하지 않는다.

성능 회귀 검증:

```powershell
$env:PYTHONPATH='.'
python scripts/benchmark_sensitive_rules.py --chars 1000000 --repeats 7
```

기본 실패 기준은 동일 실행 환경에서 기존 5종과 비교했을 때 100만 자 일반 입력의 신규 7종 추가 비용 10% 초과 또는 설정·로그형 입력의 추가 비용 25% 초과이다. 절대 시간은 장비 부하의 영향을 크게 받으므로 기본값에서는 보고만 하며, 배포 서버 기준이 정해지면 `--max-detect-median-ms`, `--max-redact-median-ms`로 별도 제한한다.

규칙을 바꾼 뒤에는 최소한 다음 테스트를 실행한다.

```powershell
python -m pytest -q app/test_sensitive_detection.py app/test_sensitive_contexts.py app/test_sensitive_redaction.py
```

## 요청 원문 로그 보호

`PII_LOG_REQUEST_TEXT_ENABLED=true`로 요청 본문 로그를 활성화한 경우, 새 기밀정보 타입은 기본적으로 로그에 원문 대신 `[REDACTED:<TYPE>]`으로 기록된다.

```dotenv
PII_LOG_REQUEST_TEXT_REDACT_SENSITIVE=true
```

마스킹 중 오류가 발생하면 요청 원문을 남기지 않고 `[REDACTION_FAILED]`만 기록하는 fail-closed 방식이다. 운영에서는 `PII_LOG_REQUEST_TEXT_REDACT_SENSITIVE=false`를 사용하지 않는 것을 권장한다. 이 마스킹은 새 기밀정보 타입을 대상으로 하며, 모든 개인정보 타입의 비식별화를 보장하는 범용 로그 마스커는 아니다.

## 호환성

기존 탐지 타입과 필드는 변경하지 않는다. HTTP/gRPC 응답 필드는 추가 방식이며, 신규 타입을 인식하지 않는 연동 클라이언트는 미지의 필드를 무시할 수 있어야 한다. gRPC 정적 클라이언트가 신규 필드를 사용하려면 갱신된 `pii.proto`로 코드를 다시 생성해야 한다.
