# 기밀정보 탐지 52번 서버 검증 결과

## 실행 정보

- 실행일: 2026-08-27 KST
- 서버: `10.100.40.52`
- 설치 경로: `/data01/xcn-pii-secret-detection`
- 애플리케이션 기반 버전: `1.0.9`
- feature 이미지 태그: `secret-detection-cd7cb23`
- 테스트 브랜치 HEAD: `d53fb8c`
- HTTP 테스트 주소: `http://127.0.0.1:18005`
- gRPC 테스트 주소: `127.0.0.1:15051`
- 운영 서비스 주소 `8005`, `50055`는 변경하거나 중단하지 않았다.

## 자동 테스트 결과

테스트케이스 31개를 HTTP/gRPC 및 `default`/`strict` 룰셋에 각각 실행했다.

| 구분 | 전체 | 통과 | 실패 |
| --- | ---: | ---: | ---: |
| HTTP | 62 | 60 | 2 |
| gRPC | 62 | 60 | 2 |
| `default` | 62 | 60 | 2 |
| `strict` | 62 | 60 | 2 |
| 합계 | 124 | 120 | 4 |

신규 기밀정보 기능의 양성·음성·경계 케이스는 모든 인터페이스와 룰셋에서 통과했다.

- `OTP`: 한국어/영문 라벨, 4자리·8자리 경계 통과
- `API_KEY`: AWS, GitHub, 일반 고엔트로피 키 통과
- `AUTH_TOKEN`: Bearer, JWT, refresh token, Basic 통과
- `PASSWORD`: 한국어, 따옴표, 공백 포함 값 통과
- `INTERNAL_ACCESS`: 사설 IPv4, loopback IPv6, 내부 URL, 내부 호스트 통과
- 음성 케이스: 라벨 없는 값, 저엔트로피 키, 공인 IPv4/IPv6, 외부 URL, 짧은 토큰, 잘못된 IP 모두 미탐지 통과
- 혼합 입력에서 신규 5개 타입 동시 탐지 통과
- count/list 일치 및 `start`/`end` offset 검증 통과

## 실패 4건

실패는 모두 `R01` 한 케이스를 네 조합에서 실행한 결과다.

| 인터페이스 | 룰셋 | 입력 | 기대 | 실제 |
| --- | --- | --- | --- | --- |
| HTTP | `default` | `연락처: 010-1234-5678` | `MN` 탐지 | 결과 없음 |
| HTTP | `strict` | `연락처: 010-1234-5678` | `MN` 탐지 | 결과 없음 |
| gRPC | `default` | `연락처: 010-1234-5678` | `MN` 탐지 | 결과 없음 |
| gRPC | `strict` | `연락처: 010-1234-5678` | `MN` 탐지 | 결과 없음 |

원인은 기존 `app/rules/mn.yaml`의 `reject_010_0_or_1xxx_4digit_middle: true` 정책이다. 이 정책은 공공기관·내부번호 오탐 방지를 위해 `010-0xxx-xxxx`와 `010-1xxx-xxxx`를 의도적으로 제외한다. 같은 문맥의 대조군 `연락처: 010-2234-5678`은 네 조합 모두 `MN`으로 정상 탐지됐다.

따라서 신규 기밀정보 기능의 회귀가 아니라 기존 MN 정책과 사용자 기대 사이의 불일치다. `010-1xxx-xxxx`를 허용하려면 별도 정책 변경과 MN 오탐 회귀 검증이 필요하다.

## 요청 로그 마스킹 결과

HTTP와 gRPC 각각 고유 마커가 있는 요청을 전송해 실제 파일 로그를 검사했다.

| 항목 | HTTP | gRPC |
| --- | --- | --- |
| 요청 마커 기록 | PASS | PASS |
| OTP 원문 미기록 | PASS | PASS |
| API Key 원문 미기록 | PASS | PASS |
| 인증토큰 원문 미기록 | PASS | PASS |
| 비밀번호 원문 미기록 | PASS | PASS |
| 내부접속정보 원문 미기록 | PASS | PASS |
| `[REDACTED:<TYPE>]` 기록 | PASS | PASS |
| `sensitive_redaction=applied` 기록 | PASS | PASS |

## 서버 산출물과 상태

- JSON 결과: `/data01/xcn-pii-secret-detection/test-results/sensitive-detection-report.json`
- 콘솔 결과: `/data01/xcn-pii-secret-detection/test-results/sensitive-detection-console.log`
- HTTP 로그: `/data01/xcn-pii-secret-detection/logs/http/sensitive-http.log`
- gRPC 로그: `/data01/xcn-pii-secret-detection/logs/grpc/sensitive-grpc.log`
- 테스트 컨테이너 2개 모두 `running`, restart count `0`
- 테스트 컨테이너 로그의 `Traceback`, `Exception`, `Error` 검색 결과 `0`
