# 기밀정보 문맥 확장 검증 결과

## 적용 정보

- 적용일: 2026-08-27 KST
- 브랜치: `feature/secret-detection`
- 적용 커밋: `9e5bacb`
- 서버: `10.100.40.52`
- 설치 경로: `/data01/xcn-pii-secret-detection`
- 이미지: `xcn-pii/api-http-cpu:secret-detection-9e5bacb`, `xcn-pii/api-grpc-cpu:secret-detection-9e5bacb`
- 테스트 포트: HTTP `18005`, gRPC `15051`

기존 운영 서비스의 `8005`, `50055` 포트와 1.0.9 컨테이너는 변경하거나 중단하지 않았다.

## 확장 범위

- OTP: MFA, 2FA, TOTP, HOTP, 로그인·본인확인·보안·다단계 인증 코드와 값 우선 문장
- API Key: JSON/camelCase/header/환경변수 문맥과 GitLab, Hugging Face, npm, SendGrid, Twilio 공급자 형식
- 인증토큰: Proxy-Authorization, Token scheme, session/CSRF/XSRF/OAuth/SSO/ID token과 한국어 토큰 문맥
- 비밀번호: JSON/YAML/환경변수, `password is`, CLI `--password`, XML, 한국어 조사·입력 지시
- 내부접속정보: JDBC 및 DB/Redis/Kafka/LDAP/WebSocket URL, 사설 CIDR, DB/cache/broker/VPN/bastion 문맥, Unix socket
- 긴 문맥 정규식의 `verbose` flag와 `prefilter_any` 지원

## 자동 검증 결과

83개 케이스를 HTTP/gRPC와 `default`/`strict` 룰셋에 각각 적용해 총 332건을 실행했다.

| 구분 | 전체 | 통과 | 실패 |
| --- | ---: | ---: | ---: |
| HTTP | 166 | 164 | 2 |
| gRPC | 166 | 164 | 2 |
| `default` | 166 | 164 | 2 |
| `strict` | 166 | 164 | 2 |
| 합계 | 332 | 328 | 4 |

세부 결과:

- 기본 신규 타입 양성 케이스: 72/72 통과
- 추가 문맥 `C01`~`C37`: 148/148 통과
- 음성·오탐 방지 케이스: 104/104 통과
- 기존 MN 허용 대조군 `010-2234-5678`: 4/4 통과
- 기존 MN 정책 불일치 `010-1234-5678`: 0/4 통과

실패 4건은 기존 `reject_010_0_or_1xxx_4digit_middle=true` 정책으로 인한 `R01`이며 이번 기밀정보 문맥 확장과 무관하다.

## 경계 오탐 보정

초기 로그 마스킹 점검에서 `CTXLOG_HTTP_20260827 MFA code: 739201`의 날짜 `20260827`이 값 우선 OTP 문맥으로 추가 탐지됐다. 값 우선 OTP 규칙에 영어 `is/equals` 또는 한국어 조사를 필수화해 보정했다.

최종 exact 검증 결과는 모든 조합에서 다음과 같다.

```text
입력: CTXLOG_HTTP_20260827 MFA code: 739201
OTP: [739201]
```

## 요청 로그 마스킹

확장 문맥을 사용한 HTTP와 gRPC 요청 모두 다음 조건을 통과했다.

- OTP/API Key/인증토큰/비밀번호/내부접속정보 원문 미기록
- 5개 `[REDACTED:<TYPE>]` 마커 기록
- `sensitive_redaction=applied` 기록

## 성능 확인

로컬에서 기밀정보가 없는 약 115만 자 텍스트를 신규 5개 detector로 스캔했다.

- 문맥 확장 직후: 약 3.1초
- `prefilter_any` 적용 후: 약 0.31초

측정값은 개발 PC 단일 실행 기준이며 운영 성능 보증값은 아니다. 문맥이나 공급자 prefix가 없는 규칙 실행을 건너뛰어 장문 입력의 불필요한 정규식 스캔을 줄였다.

## 서버 결과 파일

- JSON: `/data01/xcn-pii-secret-detection/test-results/sensitive-detection-report-context-expanded-final.json`
- 콘솔: `/data01/xcn-pii-secret-detection/test-results/sensitive-detection-console-context-expanded-final.log`
- HTTP 로그: `/data01/xcn-pii-secret-detection/logs/http/sensitive-http.log`
- gRPC 로그: `/data01/xcn-pii-secret-detection/logs/grpc/sensitive-grpc.log`

최종 테스트 컨테이너는 모두 `running`, restart count `0`이며 컨테이너 로그의 `Traceback`, `Exception`, `Error` 검색 결과는 0건이다.
