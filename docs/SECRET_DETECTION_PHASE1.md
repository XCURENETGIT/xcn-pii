# 고위험 시크릿 탐지 1차 보완

## 구현 범위

| 타입 | 지원 형식 | 탐지값 |
| --- | --- | --- |
| `PRIVATE_KEY` | PKCS#8, RSA, EC, DSA, OpenSSH, encrypted PEM, PGP, JSON `\\n` PEM | 개인키 armor 전체 |
| `CLOUD_CREDENTIAL` | `AWS_SECRET_ACCESS_KEY`, AWS session/security token, Azure `AccountKey` | 실제 credential 값 |
| `CONNECTION_STRING` | PostgreSQL, MySQL, MariaDB, MongoDB, Redis, AMQP credential URI, JDBC, ADO.NET, Azure Storage | 연결 문자열 전체 |
| `SIGNED_URL` | AWS presigned, GCS signed, Azure SAS, Slack/Discord webhook | URL 전체 |
| `MFA_SECRET` | `otpauth` URI의 `secret`, TOTP/HOTP/MFA seed 라벨 | Base32 seed |
| `RECOVERY_CODE` | recovery/backup/복구/백업 코드 라벨 | 코드 값 |
| `SESSION_COOKIE` | JSESSIONID, PHPSESSID, ASP.NET SessionId, connect.sid, session/access/refresh/id token cookie | 쿠키 값 |

GCP 서비스 계정 JSON의 `private_key`는 별도 클라우드 식별자가 아니라 실제 PEM 개인키를 `PRIVATE_KEY`로 탐지한다. 공개 인증서, public key, credential이 없는 DB URL, 일반 공개 URL 및 분석·환경설정 쿠키는 탐지하지 않는다.

## 직접 확인 예제

아래 값은 테스트 전용 가상값이다.

```text
AWS_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AB
postgresql://svc_user:S3cretPassw0rd@db.example.com:5432/app
https://bucket.s3.amazonaws.com/a.txt?X-Amz-Credential=AKIA123%2F20260827&X-Amz-Signature=abcdef0123456789abcdef0123456789
otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example
recovery_code=ABCD-EF12-IJKL-3456
Cookie: JSESSIONID=ABCDEF0123456789ABCDEF0123456789
```

개인키 테스트는 `app/test_secret_detection_phase1.py`의 구조적으로 유효한 가상 Base64 본문을 사용한다.

## 오탐 방지 예제

다음 입력은 신규 7종으로 탐지하지 않는다.

```text
-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----
AWS_SECRET_ACCESS_KEY=changeme
postgresql://db.example.com:5432/app
https://example.com/public?sig=abcdef
TOTP generates a six digit code
JBSWY3DPEHPK3PXP
recovery code documentation
Cookie: theme=dark; locale=ko-KR
JSESSIONID=short
```

## 검증 명령

```powershell
python -m pytest -q app/test_secret_detection_phase1.py
$env:PYTHONPATH='.'
python scripts/benchmark_sensitive_rules.py --chars 1000000 --repeats 7
```

성능 도구는 기존 5종과 신규 포함 12종을 동일 입력에서 번갈아 실행해 중앙값을 비교한다. 일반 문서와 `key=value`, timestamp, 공개 endpoint가 반복되는 설정·로그형 문서를 각각 측정한다.
