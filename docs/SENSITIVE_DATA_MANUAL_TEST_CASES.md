# 신규 기밀정보 탐지 수동 테스트 전체 목록

## 1. 문서 목적과 범위

이 문서는 `feature/secret-detection` 브랜치에서 추가한 다음 5개 타입을 사용자가 직접 시험할 수 있도록 현재 구현된 모든 **패턴군, 공급자 형식, 문맥 별칭, 내부 URL scheme, 정상·비탐지 경계**를 정리한 문서다.

Unicode·escape encoding·Markdown·구분자 제거와 같은 우회 방어 범위와 잔여 한계는 `docs/SENSITIVE_EVASION_HARDENING.md`를 함께 참조한다.

| 타입 | 의미 | HTTP 결과 필드 | gRPC 결과 필드 |
| --- | --- | --- | --- |
| `OTP` | OTP·인증·확인 코드 | `OTP_CNT`, `OTP` | `otp_cnt`, `otp` |
| `API_KEY` | 공급자 전용 키와 라벨 기반 일반 키 | `API_KEY_CNT`, `API_KEY` | `api_key_cnt`, `api_key` |
| `AUTH_TOKEN` | JWT, 인증 헤더, 인증·세션 토큰 | `AUTH_TOKEN_CNT`, `AUTH_TOKEN` | `auth_token_cnt`, `auth_token` |
| `PASSWORD` | 라벨에 할당된 비밀번호 | `PASSWORD_CNT`, `PASSWORD` | `password_cnt`, `password` |
| `INTERNAL_ACCESS` | 사설 주소, 내부 호스트·URL·socket | `INTERNAL_ACCESS_CNT`, `INTERNAL_ACCESS` | `internal_access_cnt`, `internal_access` |

여기서 “모든 케이스”는 만들 수 있는 모든 실제 문자열의 무한한 조합이 아니라, 현재 규칙이 지원하는 모든 형식과 분기 조건을 뜻한다. 문서의 키와 비밀번호는 전부 테스트용 가짜 값이다. 실제 운영 기밀을 테스트 요청에 넣지 않는다.

이 문서에 수록된 `AK01`~`AK25`, `IA01`~`IA36`, `OT01`~`OT05`, `GK01`~`GK05`, `AT01`~`AT06`, `PW01`~`PW06`, `NG01`~`NG13`은 `app/test_sensitive_manual_examples.py`에서 자동 검증한다.

## 2. 바로 실행하는 방법

52번 서버의 분리된 기능 시험 환경은 다음 주소를 사용한다.

- HTTP: `http://10.100.40.52:18005`
- gRPC: `10.100.40.52:15051`
- ruleset: `default` 또는 `strict`

### 2.1 PowerShell HTTP 테스트

`$text`만 아래 표의 입력으로 바꿔 반복 실행한다.

```powershell
$text = 'OTP=1234'
$body = @{
    text = $text
    max_results_per_type = 100
} | ConvertTo-Json

$response = Invoke-RestMethod `
    -Method Post `
    -Uri 'http://10.100.40.52:18005/pii/detect' `
    -ContentType 'application/json; charset=utf-8' `
    -Headers @{ 'X-PII-RULESET' = 'default' } `
    -Body ([System.Text.Encoding]::UTF8.GetBytes($body))

$response.data | ConvertTo-Json -Depth 8
```

예상 결과는 해당 타입의 `*_CNT`가 1 이상이고, 배열의 `matchString`이 표의 예상 값과 같아야 한다. 어떤 규칙에서 탐지했는지는 `detected_by`로 확인한다.

### 2.2 Linux curl HTTP 테스트

```bash
curl -sS -X POST 'http://10.100.40.52:18005/pii/detect' \
  -H 'Content-Type: application/json' \
  -H 'X-PII-RULESET: default' \
  -d '{"text":"OTP=1234","max_results_per_type":100}'
```

### 2.3 grpcurl 테스트

```bash
grpcurl -plaintext \
  -d '{"text":"OTP=1234","max_results_per_type":100,"ruleset":"default"}' \
  10.100.40.52:15051 xcn.pii.v1.PiiDetector/Detect
```

gRPC에서는 `matchString` 대신 JSON 출력의 `matchString` 또는 사용하는 클라이언트 언어의 `match_string` 필드로 확인한다.

### 2.4 5개 타입 한 번에 확인

```text
인증번호: 482913
API_KEY=abcDEF1234567890xyz
Authorization: Bearer AbCdEf0123456789-token.value
비밀번호: S3cure!Pass#2026
내부 URL: postgresql://svc:FakePass@db01.internal:5432/app
```

예상 count는 `OTP_CNT=1`, `API_KEY_CNT=1`, `AUTH_TOKEN_CNT=1`, `PASSWORD_CNT=1`, `INTERNAL_ACCESS_CNT=1`이다.

## 3. OTP 전체 지원 범위

### 3.1 값 형식과 위치

- 값은 숫자만 허용하며 길이는 4~8자리다.
- 라벨이 값 앞에 있는 형식과 값이 라벨 앞에 있는 형식을 모두 지원한다.
- 값 앞 라벨은 `:`, `=`, `-`, `#`, `>`, 따옴표, 대괄호·소괄호와 한국어 조사 및 `is`, `equals`, `value is`, `code is`를 지원한다.
- 값 우선 문장은 오탐 방지를 위해 `482913은 ...`, `482913번은 ...`, `739201 is your ...`, `739201 equals ...`처럼 값과 라벨 사이의 명시적인 연결어가 필요하다.

### 3.2 지원 라벨 전체 목록

| 구분 | 지원 라벨 |
| --- | --- |
| 영문 약어 | `OTP`, `TOTP`, `HOTP`, `MFA`, `2FA` 및 뒤의 선택적 `code`, `number`, `pin`, `password`, `passcode` |
| 영문 일회용 | `one-time`, `one_time`, `one time`, `single-use` + `password`, `passcode`, `code`, `pin` |
| 영문 인증 문맥 | `verification`, `authentication`, `security`, `confirmation`, `login`, `sign-in`, `multi-factor`, `two-factor` + `code`, `number`, `pin`, `passcode` |
| 한국어 약어 | `OTP`, `TOTP`, `HOTP`, `MFA`, `2FA` + 선택적 `번호`, `코드`, `PIN`, `비밀번호` |
| 한국어 인증 문맥 | `인증`, `확인`, `보안`, `본인확인`, `로그인`, `접속`, `다단계 인증`, `이중 인증`, `2차 인증` + `번호`, `코드`, `PIN` |
| 한국어 일회용 | `일회용` + `비밀번호`, `암호`, `번호`, `코드`, `PIN` |

### 3.3 직접 테스트 케이스

| ID | 입력 | 예상 값 | `detected_by` |
| --- | --- | --- | --- |
| OT01 | `OTP=1234` | `1234` | `otp_context_before` |
| OT02 | `MFA code: 739201` | `739201` | `otp_context_before` |
| OT03 | `본인확인 코드 [551122]` | `551122` | `otp_context_before` |
| OT04 | `482913은 인증번호입니다` | `482913` | `otp_context_after` |
| OT05 | `12345678 is your one-time password` | `12345678` | `otp_context_after` |

추가 조합 예: `TOTP_CODE=552211`, `HOTP PIN: 778899`, `security passcode is 447711`, `로그인 코드는 663311`, `2차 인증 번호: 994411`, `일회용 비밀번호는 775533`.

## 4. API_KEY 전체 지원 범위

공급자 전용 형식은 주변 라벨 없이 prefix와 구조만으로 탐지한다. 표의 입력은 그대로 붙여 넣어 시험할 수 있다.

### 4.1 공급자 전용 형식 전체

| ID | 공급자·형식 | 입력 및 예상 값 | `detected_by` |
| --- | --- | --- | --- |
| AK01 | AWS `AKIA` + 16자 | `AKIAIOSFODNN7EXAMPLE` | `aws_access_key_id` |
| AK02 | AWS `ASIA` + 16자 | `ASIAIOSFODNN7EXAMPLE` | `aws_access_key_id` |
| AK03 | GitHub `ghp_` + 36자 이상 | `ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8` | `github_token` |
| AK04 | GitHub `gho_` + 36자 이상 | `gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8` | `github_token` |
| AK05 | GitHub `ghu_` + 36자 이상 | `ghu_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8` | `github_token` |
| AK06 | GitHub `ghs_` + 36자 이상 | `ghs_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8` | `github_token` |
| AK07 | GitHub `ghr_` + 36자 이상 | `ghr_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8` | `github_token` |
| AK08 | GitHub fine-grained | `github_pat_11AA22BB33CC44DD55EE66FF` | `github_token` |
| AK09 | Google `AIza` + 35자 | `AIzaAbCdEfGhIjKlMnOpQrStUvWxYz012345678` | `google_api_key` |
| AK10 | Slack `xoxb-` | `xoxb-1234567890-AbCdEfGhIjKlMnOp` | `slack_token` |
| AK11 | Slack `xoxa-` | `xoxa-1234567890-AbCdEfGhIjKlMnOp` | `slack_token` |
| AK12 | Slack `xoxp-` | `xoxp-1234567890-AbCdEfGhIjKlMnOp` | `slack_token` |
| AK13 | Slack `xoxr-` | `xoxr-1234567890-AbCdEfGhIjKlMnOp` | `slack_token` |
| AK14 | Slack `xoxs-` | `xoxs-1234567890-AbCdEfGhIjKlMnOp` | `slack_token` |
| AK15 | OpenAI `sk-` | `sk-AbCdEfGhIjKlMnOpQrStUvWx` | `openai_api_key` |
| AK16 | OpenAI `sk-proj-` | `sk-proj-AbCdEfGhIjKlMnOpQrStUvWx` | `openai_api_key` |
| AK17 | Stripe `sk_live_` | `sk_live_AbCdEfGhIjKlMnOp` | `stripe_secret_key` |
| AK18 | Stripe `sk_test_` | `sk_test_AbCdEfGhIjKlMnOp` | `stripe_secret_key` |
| AK19 | Stripe `rk_live_` | `rk_live_AbCdEfGhIjKlMnOp` | `stripe_secret_key` |
| AK20 | Stripe `rk_test_` | `rk_test_AbCdEfGhIjKlMnOp` | `stripe_secret_key` |
| AK21 | GitLab `glpat-` | `glpat-AbCdEfGhIjKlMnOpQrStUvWx` | `gitlab_token` |
| AK22 | Hugging Face `hf_` | `hf_abcdefghijklmnopqrstuvwxyzABCDEFGH` | `huggingface_token` |
| AK23 | npm `npm_` | `npm_abcdefghijklmnopqrstuvwxyzABCDEFGH` | `npm_token` |
| AK24 | SendGrid `SG.<16+>.<16+>` | `SG.AbCdEfGhIjKlMnOp.QrStUvWxYz012345` | `sendgrid_api_key` |
| AK25 | Twilio `SK` + 32자리 hex | `SK0123456789abcdef0123456789abcdef` | `twilio_api_key` |

### 4.2 일반 API Key 문맥 전체

일반 키 값은 16~512자이고 `[A-Za-z0-9_./+~=-]`만 허용한다. Shannon entropy 3.0 이상, 문자 종류 2개 이상이어야 한다.

| 구분 | 지원 라벨 |
| --- | --- |
| API key | `x-api-key`, `api key`와 공백 대신 `_`, `.`, `-`를 쓴 변형 |
| 영문 key | `access`, `secret`, `private`, `application`, `app`, `service`, `subscription`, `consumer`, `signing` + `key` |
| 영문 secret | `api`, `application`, `app`, `client`, `consumer`, `webhook`, `signing` + `secret` |
| APIM | `Ocp-Apim-Subscription-Key` 및 구분자 변형 |
| 한국어 key | `API`, `애플리케이션`, `응용 프로그램`, `앱`, `접근`, `액세스`, `비밀`, `서비스`, `구독`, `소비자`, `서명` + `키` 또는 `Key` |
| 한국어 secret | `클라이언트`, `앱`, `웹훅`, `서명` + `시크릿` 또는 `비밀` |
| 할당 방식 | JSON/YAML/env의 따옴표 키, 조사 `은/는/이/가`, `is`, `equals`, `value is`, `:`, `=`, `=>` |
| 강한 라벨 + bounded separator | `API_KEY`, `API Key`, `x-api-key`, `Ocp-Apim-Subscription-Key`, `API 키` 뒤 최대 8자의 공백·개행 또는 `|`, `->`, `=>`로 값 표기 |
| 값 우선 영문 | `<값> is/equals the/your <service key 등>` |

| ID | 입력 | 예상 값 | `detected_by` |
| --- | --- | --- | --- |
| GK01 | `{"apiKey":"AbCDef1234567890xyz"}` | `AbCDef1234567890xyz` | `generic_api_key` |
| GK02 | `Ocp-Apim-Subscription-Key: Az9xY8wV7uT6sR5qP4nM3kL2` | `Az9xY8wV7uT6sR5qP4nM3kL2` | `generic_api_key` |
| GK03 | `웹훅 시크릿: whsec_Z9y8X7w6V5u4T3s2R1q0` | `whsec_Z9y8X7w6V5u4T3s2R1q0` | `generic_api_key` |
| GK04 | `SvcK3y-2026-AbCdEfGh is the service key` | `SvcK3y-2026-AbCdEfGh` | `generic_api_key_context_after` |
| GK05 | `API_KEY abcDEF1234567890xyz` | `abcDEF1234567890xyz` | `generic_api_key` |

공백·개행-only 구분은 과탐을 제한하기 위해 위의 강한 API Key 라벨에만 적용한다. Markdown wrapper는 최대 3자, separator는 최대 8자로 제한한다. `service key <값>` 같은 약한 라벨에는 적용하지 않으며 값에는 기존과 동일하게 길이, entropy, 문자 종류 조건을 적용한다.

## 5. AUTH_TOKEN 전체 지원 범위

### 5.1 지원 패턴과 라벨

| 패턴 | 조건 | `detected_by` |
| --- | --- | --- |
| JWT | `eyJ...`.`eyJ...`.`signature` 3개 구간 | `jwt` |
| Bearer | 선택적 `Authorization`/`Proxy-Authorization` 뒤 `Bearer <16자 이상>` 또는 독립 `Bearer` | `bearer_token` |
| Basic | `Authorization`/`Proxy-Authorization: Basic <base64>` | `basic_auth_token` |
| Token scheme | `Authorization`/`Proxy-Authorization: Token <16자 이상>` | `authorization_token_scheme` |
| 영문 라벨 | 선택적 `x-` + `access`, `refresh`, `auth`, `authentication`, `authorization`, `identity`, `id`, `session`, `security`, `oauth`, `sso`, `csrf`, `xsrf`, `api` + `token` |
| 단독 라벨 | `token`, `jwt`, `sessionid`, `session-id`, `session_id` |
| 한국어 라벨 | `인증`, `인가`, `접근`, `액세스`, `갱신`, `리프레시`, `세션`, `보안`, `OAuth`, `SSO`, `CSRF`, `API` + `토큰`; `인증 ID`, `세션 ID` |
| 할당 방식 | JSON/YAML/env의 따옴표 키, 조사, `is`, `equals`, `value is`, `:`, `=`, `=>` |
| 값 우선 영문 | `<값> is/equals the/your <access token 등>` |

라벨 기반 값은 16~4096자, 문자 집합 `[A-Za-z0-9._~+/=-]`, entropy 2.5 이상이다.

### 5.2 직접 테스트 케이스

| ID | 입력 | 예상 값 | `detected_by` |
| --- | --- | --- | --- |
| AT01 | `Authorization: Bearer AbCdEf0123456789-token.value` | `AbCdEf0123456789-token.value` | `bearer_token` |
| AT02 | `Authorization: Basic dXNlcjpTM2NyZXQh` | `dXNlcjpTM2NyZXQh` | `basic_auth_token` |
| AT03 | `Authorization: Token Tok3n-Header-2026.AbCd` | `Tok3n-Header-2026.AbCd` | `authorization_token_scheme` |
| AT04 | `jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature123` | JWT 전체 | `jwt` |
| AT05 | `{"X-Auth-Token":"Auth-2026.AbCdEfGhIjKl"}` | `Auth-2026.AbCdEfGhIjKl` | `labeled_auth_token` |
| AT06 | `Tok3n-2026.AbCdEfGhIjKl is the access token` | `Tok3n-2026.AbCdEfGhIjKl` | `auth_token_context_after` |

## 6. PASSWORD 전체 지원 범위

### 6.1 지원 라벨과 표현

| 구분 | 지원 항목 |
| --- | --- |
| 기본 영문 | `password`, `passwd`, `pwd`, `passphrase` |
| 영문 접두 라벨 | `db`, `database`, `user`, `account`, `admin`, `root`, `login`, `service`, `current`, `new`, `old`, `temp`, `temporary`, `default` + `password`, `passwd`, `pwd` |
| 기본 한국어 | `비밀번호`, `암호` |
| 한국어 접두 라벨 | `로그인`, `계정`, `사용자`, `관리자`, `루트`, `DB`, `데이터베이스`, `서비스`, `현재`, `기존`, `새`, `신규`, `임시`, `초기` + `비밀번호`, `암호` |
| 할당 형식 | JSON/YAML/env, 큰따옴표·작은따옴표·무따옴표 값, 조사와 `다음과 같습니다`, `is`, `equals`, `:`, `=`, `=>` |
| CLI | `--password`, `--passwd`, `--pwd` 뒤 큰따옴표·작은따옴표·무따옴표 값 |
| XML | `<password>`, `<passwd>`, `<pwd>` 요소 |
| 한국어 지시 | `비밀번호/암호를 입력/사용/설정/변경...: <값>` |

따옴표 안에서는 공백을 포함한 1~256자 값을 탐지한다. 무따옴표 값은 공백, 쉼표, 세미콜론, 따옴표, 꺾쇠괄호 전까지 탐지한다.

### 6.2 직접 테스트 케이스

| ID | 입력 | 예상 값 | `detected_by` |
| --- | --- | --- | --- |
| PW01 | `{"password":"Json!Pass-2026"}` | `Json!Pass-2026` | `labeled_password` |
| PW02 | `DB_PASSWORD='Db Pass! 2026'` | `Db Pass! 2026` | `labeled_password` |
| PW03 | `tool --password Cli!Pass-2026 --verbose` | `Cli!Pass-2026` | `password_cli_argument` |
| PW04 | `tool --pwd "Cli Pass! 2026"` | `Cli Pass! 2026` | `password_cli_argument` |
| PW05 | `<password>Xml!Pass-2026</password>` | `Xml!Pass-2026` | `password_xml_element` |
| PW06 | `비밀번호를 입력하세요: Input!Pass-2026` | `Input!Pass-2026` | `password_instruction` |

## 7. INTERNAL_ACCESS 전체 지원 범위

### 7.1 내부 URL scheme 전체

URL은 scheme만 맞는다고 탐지하지 않는다. hostname이 사설·loopback·link-local IP, `localhost`, 단일 호스트명 또는 7.3절의 내부 suffix여야 한다.

| ID | scheme | 입력 및 예상 값 |
| --- | --- | --- |
| IA01 | `http` | `http://app01.internal:8080/api` |
| IA02 | `https` | `https://app01.internal/api` |
| IA03 | `ssh` | `ssh://admin@jump01.corp:22` |
| IA04 | `sftp` | `sftp://files01.internal:22/in` |
| IA05 | `ftp` | `ftp://files01.internal/in` |
| IA06 | `postgres` | `postgres://svc:FakePass@db01.internal:5432/app` |
| IA07 | `postgresql` | `postgresql://svc:FakePass@db01.internal:5432/app` |
| IA08 | `jdbc:postgresql` | `jdbc:postgresql://db01.internal:5432/app` |
| IA09 | `mysql` | `mysql://svc:FakePass@db01.internal:3306/app` |
| IA10 | `jdbc:mysql` | `jdbc:mysql://db01.internal:3306/app` |
| IA11 | `mariadb` | `mariadb://db01.internal:3306/app` |
| IA12 | `mssql` | `mssql://sql01.internal:1433/app` |
| IA13 | `sqlserver` | `sqlserver://sql01.internal:1433/app` |
| IA14 | `oracle` | `oracle://ora01.internal:1521/XEPDB1` |
| IA15 | `mongodb` | `mongodb://mongo01.internal:27017/app` |
| IA16 | `mongodb+srv` | `mongodb+srv://mongo01.internal/app` |
| IA17 | `redis` | `redis://cache01.internal:6379/0` |
| IA18 | `rediss` | `rediss://cache01.internal:6380/0` |
| IA19 | `amqp` | `amqp://mq01.internal:5672/vhost` |
| IA20 | `amqps` | `amqps://mq01.internal:5671/vhost` |
| IA21 | `kafka` | `kafka://broker01.internal:9092/topic` |
| IA22 | `nats` | `nats://nats01.internal:4222` |
| IA23 | `ldap` | `ldap://ldap01.internal:389` |
| IA24 | `ldaps` | `ldaps://ldap01.internal:636` |
| IA25 | `rmi` | `rmi://java01.internal:1099/service` |
| IA26 | `tcp` | `tcp://collector01.internal:9000` |
| IA27 | `ws` | `ws://socket01.internal:8080/ws` |
| IA28 | `wss` | `wss://socket01.internal/ws` |

IA01~IA28의 `detected_by`는 모두 `internal_url`이다. `jdbc:` 접두사는 현재 `postgresql`, `mysql`을 포함해 규칙에 열거된 DB scheme 앞에 사용할 수 있다.

### 7.2 IP, CIDR, 호스트, socket

| ID | 입력 | 예상 값 | `detected_by` |
| --- | --- | --- | --- |
| IA29 | `내부 IP: 10.20.30.40` | `10.20.30.40` | `private_ipv4` |
| IA30 | `내부 IP: fd00::10` | `fd00::10` | `private_ipv6` |
| IA31 | `internal subnet 10.20.0.0/16` | `10.20.0.0/16` | `private_network` |
| IA32 | `internal subnet fd00:1234::/64` | `fd00:1234::/64` | `private_network` |
| IA33 | `DB_HOST=db01` | `db01` | `internal_host` |
| IA34 | `endpoint="app01.svc.cluster.local:8080"` | `app01.svc.cluster.local:8080` | `internal_host` |
| IA35 | `socket_path=/var/run/postgresql/.s.PGSQL.5432` | `/var/run/postgresql/.s.PGSQL.5432` | `internal_socket_path` |
| IA36 | `유닉스 소켓은 unix:/run/redis/redis.sock` | `unix:/run/redis/redis.sock` | `internal_socket_path` |

사설 주소 판정에는 IPv4/IPv6의 private, loopback, link-local 범위가 포함된다. 따라서 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`에 속하는 유효 주소·CIDR을 탐지할 수 있다.

### 7.3 내부 hostname 판정 전체

- `localhost`
- 점이 없는 단일 호스트명: `db01`, `vpn-gw`
- 사설·loopback·link-local IP와 선택적 포트
- suffix: `.internal`, `.local`, `.lan`, `.corp`, `.intranet`, `.svc`, `.svc.cluster.local`, `.cluster.local`, `.home.arpa`, `.private`, `.localdomain`

### 7.4 호스트 라벨 전체

| 구분 | 지원 라벨 |
| --- | --- |
| 영문 환경 접두어 | 선택적 `internal`, `private`, `intranet`, `corp`, `office`, `production`, `prod`, `development`, `dev`, `staging`, `stage`, `test` |
| 영문 대상 | `server`, `host`, `hostname`, `endpoint`, `address`, `gateway`, `proxy`, `vpn`, `bastion`, `jump host`, `database`, `db`, `redis`, `cache`, `mongo`, `mongodb`, `kafka`, `broker`, `elasticsearch` |
| 영문 선택 suffix | `server`, `host`, `hostname`, `address`, `addr`, `ip`, `endpoint`, `url` |
| 한국어 환경 접두어 | 선택적 `내부`, `사내`, `업무`, `관리`, `운영`, `개발`, `검증`, `테스트`, `스테이징`, `운영계`, `개발계` |
| 한국어 대상 | `접속 주소/정보/IP`, `서버 주소/IP`, `호스트/호스트명`, `엔드포인트`, `주소`, `게이트웨이`, `프록시`, `VPN 주소/서버`, `배스천 호스트/서버`, `점프 호스트/서버`, `DB`, `데이터베이스`, `캐시`, `레디스`, `몽고`, `카프카`, `브로커`와 각 주소·서버·호스트 변형 |
| socket | `unix socket`, `socket path`, `socket`, `소켓 경로`, `소켓 주소`, `유닉스 소켓` |
| 할당 방식 | JSON/YAML/env 따옴표 키, 조사, `is`, `equals`, `:`, `=`, `=>` |

## 8. 비탐지 경계 케이스

다음 입력은 표의 해당 타입이 **0건**이어야 정상이다. 다른 기존 개인정보 타입이 별도로 잡히는지는 이 표의 판정 대상이 아니다.

| ID | 입력 | 0건이어야 하는 타입 | 이유 |
| --- | --- | --- | --- |
| NG01 | `주문번호 482913` | `OTP` | OTP 문맥 없음 |
| NG02 | `OTP=123` | `OTP` | 4자리 미만 |
| NG03 | `OTP=123456789` | `OTP` | 8자리 초과 |
| NG04 | `API_KEY=AAAAAAAAAAAAAAAAAAAA` | `API_KEY` | entropy·문자 종류 부족 |
| NG05 | `public_key=AbCDef1234567890xyz` | `API_KEY` | 공개키는 일반 API key 라벨에서 제외 |
| NG06 | `Authorization: Bearer short-token` | `AUTH_TOKEN` | 16자 미만 |
| NG07 | `{"token":"short"}` | `AUTH_TOKEN` | 길이·entropy 부족 |
| NG08 | `password policy requires 12 characters` | `PASSWORD` | 값 할당이 아닌 설명 문장 |
| NG09 | `--password-help shows usage` | `PASSWORD` | CLI 값 인수가 아님 |
| NG10 | `DNS server: 8.8.8.8` | `INTERNAL_ACCESS` | 공인 IPv4 |
| NG11 | `endpoint: https://example.com/api` | `INTERNAL_ACCESS` | 공개 URL |
| NG12 | `public subnet 8.8.8.0/24` | `INTERNAL_ACCESS` | 공인 CIDR |
| NG13 | `DB_HOST=example.com` | `INTERNAL_ACCESS` | 공개 hostname |

추가 경계:

- `MFA rollout requires a six digit code`와 `verification code length is 6`은 OTP 값이 없으므로 비탐지다.
- `client secret rotation policy`, `token validation documentation`은 할당 값이 없으므로 비탐지다.
- `socket documentation at /docs/socket`은 socket 할당 형식이 아니므로 비탐지다.
- `010-1234-5678`은 신규 타입이 아니라 기존 `MN` 규칙의 대상이다. 현재 MN 정책의 `010-0xxx/1xxx` 중간번호 제외 옵션에 따라 결과가 달라질 수 있으며 이 문서의 신규 5개 타입 판정과는 별개다.

## 9. 결과 판정 체크리스트

각 케이스를 실행한 뒤 다음을 확인한다.

1. 예상 타입의 count가 1 이상인지 확인한다.
2. 배열의 `matchString`이 라벨이나 구분자를 포함하지 않고 표의 **예상 값만** 반환하는지 확인한다.
3. `detected_by`가 표와 같은지 확인한다.
4. `start`와 `end`로 원문을 잘랐을 때 `matchString`과 같은지 확인한다.
5. NG 케이스는 해당 신규 타입 배열이 없거나 빈 배열이고 count가 0인지 확인한다.
6. 같은 입력을 `default`, `strict` ruleset과 HTTP, gRPC 양쪽에서 실행해 결과가 일치하는지 확인한다.

로컬 전체 문서 예시 검증 명령:

```powershell
& 'C:\xcn_prj\xcn-pii\.venv\Scripts\python.exe' -m pytest -q app/test_sensitive_manual_examples.py
```

기존 신규 탐지 회귀 테스트까지 포함한 검증 명령:

```powershell
& 'C:\xcn_prj\xcn-pii\.venv\Scripts\python.exe' -m pytest -q `
    app/test_sensitive_detection.py `
    app/test_sensitive_contexts.py `
    app/test_sensitive_redaction.py `
    app/test_sensitive_manual_examples.py
```
