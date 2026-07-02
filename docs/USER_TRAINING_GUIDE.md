# XCN-PII 사용자 교육 자료

이 문서는 XCN-PII를 처음 사용하는 운영자와 연동 개발자가 빠르게 이해하고 테스트할 수 있도록 정리한 교육용 안내서입니다.

## 1. XCN-PII가 하는 일

XCN-PII는 입력 텍스트 또는 업로드 파일에서 개인정보 후보를 탐지하는 시스템입니다.

탐지 대상은 다음 16종입니다.

| 코드 | 의미 | 예시 |
| --- | --- | --- |
| `SN` | 주민등록번호 | `900101-1234567` |
| `FN` | 외국인등록번호 | `900101-5123450` |
| `SSN` | Social Security Number | `123-45-6789` |
| `DN` | 운전면허번호 | `11-22-333333-44` |
| `PN` | 여권번호 | `M12345678` |
| `MN` | 전화번호 | `010-1234-5678` |
| `BRN` | 사업자등록번호 | `123-45-67890` |
| `BN` | 계좌번호/은행번호 | 은행 계좌 형식 |
| `AN` | 주소 | `서울시 은평구 가좌로 276` |
| `CN` | 카드번호 | `4111-1111-1111-1111` |
| `EML` | 이메일 | `test@example.com` |
| `VN_CCCD` | 베트남 시민신분증/개인식별번호 | `001234567890` |
| `VN_MN` | 베트남 휴대폰번호 | `098-123-4567` |
| `VN_PN` | 베트남 여권번호 | `B12345678` |
| `VN_TIN` | 베트남 세금번호/납세자번호 | `0312345678-001` |
| `VN_SI` | 베트남 사회보험/건강보험 코드 | `0123456789` |

베트남 10자리 계열 번호(`VN_TIN`, `VN_SI`)는 일반 숫자 오탐을 줄이기 위해 `ma so thue`, `ma so BHXH`, `BHYT` 같은 문맥 라벨과 함께 테스트하는 것을 권장합니다.

## 2. 제공 인터페이스

| 방식 | 기본 포트 | 용도 |
| --- | ---: | --- |
| HTTP API | `8005` | 기본 REST API 호출 |
| HTTPS API | `28443` | TLS 적용 REST API 호출 |
| gRPC direct | `50051` | 단일 gRPC 서버 호출 |
| gRPC LB | `50055` | HAProxy 로드밸런서 호출 |

운영 환경에서 외부에 공개할 때는 HTTPS 전용 모드를 권장합니다.

## 3. 빠른 실행

### HTTP CPU 모드

```bash
./scripts/start_http_cpu.sh
```

확인:

```bash
curl http://localhost:8005/pii/selftest
```

### HTTPS 전용 CPU 모드

먼저 인증서를 준비합니다.

```bash
./scripts/make_self_signed_cert.sh <서버IP>
```

예:

```bash
./scripts/make_self_signed_cert.sh 223.130.153.221
```

그 다음 HTTPS 전용으로 실행합니다.

```bash
./scripts/start_http_cpu_https_only.sh
```

확인:

```bash
curl -k https://localhost:28443/pii/selftest
```

HTTPS 전용 모드에서는 외부 HTTP 포트 `8005`를 열지 않고, 외부 HTTPS 포트 `28443`만 엽니다.

## 4. 개인정보 탐지 API 호출

### HTTP 호출

```bash
curl -X POST "http://localhost:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: default" \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
    "max_results_per_type": 100
  }'
```

### HTTPS 호출

자체 서명 인증서를 사용하는 테스트 환경에서는 `-k`를 붙입니다.

```bash
curl -k -X POST "https://localhost:28443/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: default" \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
    "max_results_per_type": 100
  }'
```

정상 응답에는 탐지 성공 여부, 상태 코드, 탐지 결과, 룰셋 메타 정보가 포함됩니다.

```json
{
  "success": true,
  "status": 200,
  "data": {
    "SN_CNT": 1,
    "EML_CNT": 1
  },
  "meta": {
    "ruleset_name": "default"
  }
}
```

## 5. 룰셋 선택

XCN-PII는 두 가지 기본 룰셋을 제공합니다.

| 룰셋 | 특징 |
| --- | --- |
| `default` | 문맥 필터를 포함한 기본 탐지 |
| `strict` | 더 엄격한 탐지, 일부 문맥 후처리 제외 |

HTTP에서는 `X-PII-RULESET` 헤더로 룰셋을 선택합니다.

```bash
curl -X POST "http://localhost:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -H "X-PII-RULESET: strict" \
  -d '{"text":"test@example.com","max_results_per_type":100}'
```

사용 가능한 룰셋 확인:

```bash
curl http://localhost:8005/pii/rulesets
```

## 6. Postman 사용법

### 자체 서명 인증서 테스트

Postman에서 자체 서명 인증서를 사용하는 경우 가장 빠른 테스트 방법은 SSL 검증을 끄는 것입니다.

```text
Settings -> General -> SSL certificate verification -> OFF
```

요청 설정:

| 항목 | 값 |
| --- | --- |
| Method | `POST` |
| URL | `https://<서버IP>:28443/pii/detect` |
| Header | `Content-Type: application/json` |
| Header | `X-PII-RULESET: default` |

Body -> raw -> JSON:

```json
{
  "text": "홍길동 주민번호는 900101-1234567, 이메일은 test@example.com 입니다.",
  "max_results_per_type": 100
}
```

SSL 검증을 유지하려면 Postman의 CA Certificates에 `tls.crt` 또는 PEM 파일을 등록합니다.

## 7. 자체 서명 인증서 이해

`make_self_signed_cert.sh`는 테스트 또는 내부망 검증용 자체 서명 인증서를 만듭니다.

IP로 접속할 서버라면 반드시 IP를 넣어 생성합니다.

```bash
./scripts/make_self_signed_cert.sh 223.130.153.221
```

도메인으로 접속할 서버라면 도메인을 넣습니다.

```bash
./scripts/make_self_signed_cert.sh pii.example.com
```

자체 서명 인증서는 기본적으로 클라이언트가 신뢰하지 않습니다. 따라서 다음 중 하나가 필요합니다.

| 방법 | 설명 |
| --- | --- |
| `curl -k` | 테스트용. 인증서 검증을 끔 |
| `curl --cacert certs/tls.crt` | 해당 인증서를 명시적으로 신뢰 |
| OS 신뢰 저장소 등록 | 서버/클라이언트에서 인증서를 신뢰 인증서로 등록 |
| 공인/사내 CA 인증서 사용 | 운영 권장 방식 |

## 8. 배포 패키지 만들기

### CPU 단일 패키지

```bash
docker compose -f docker-compose.http-cpu.yml --profile http build api
docker compose -f docker-compose.grpc-cpu.yml --profile grpc build api-grpc
docker pull haproxy:3.1-alpine
docker pull nginx:1.27-alpine
./scripts/package_deploy_bundle.sh --output-dir ./dist
```

생성 파일명 예:

```text
xcn-pii-all-cpu-package-1.0.0-YYYYMMDD-HHMMSS.tar.gz
```

배포 서버에서:

```bash
tar -xzf xcn-pii-all-cpu-package-*.tar.gz
cd xcn-pii
./install.sh --mode all --no-start
docker compose up -d
```

`certs/tls.crt`, `certs/tls.key`가 없으면 `install.sh`가 자체서명 HTTPS 인증서를 생성합니다. 운영 인증서는 `docker compose up -d` 전에 같은 경로로 배치합니다.

단일 패키지 모드:

```bash
./install.sh --mode grpc --no-start
docker compose up -d

./install.sh --mode http --no-start
docker compose up -d

./install.sh --mode https --no-start
docker compose up -d
```

운영 명령:

```bash
docker compose ps
docker compose logs -f
docker compose down
```

## 9. 자주 발생하는 문제

### curl: SSL certificate problem: self signed certificate

자체 서명 인증서를 클라이언트가 신뢰하지 않아서 발생합니다.

테스트:

```bash
curl -k https://<서버IP>:28443/pii/selftest
```

검증 유지:

```bash
curl --cacert certs/tls.crt https://<서버IP>:28443/pii/selftest
```

### HTTPS는 되는데 HTTP도 접속됨

일반 HTTPS 실행 스크립트는 HTTP `8005`와 HTTPS `28443`을 함께 열 수 있습니다.

외부 HTTPS만 허용하려면 HTTPS 전용 스크립트를 사용합니다.

```bash
./scripts/start_http_cpu_https_only.sh
```

### Postman에서 SSL 오류가 남

테스트 목적이면 SSL certificate verification을 끕니다.

운영 검증 목적이면 CA Certificates에 서버 인증서를 등록하고, 인증서 SAN에 접속 IP 또는 도메인이 포함되어 있는지 확인합니다.

### 포트가 열렸는지 확인

```bash
ss -lntp | grep -E ':8005|:28443|:50055'
```

HTTPS 전용 모드라면 `28443`은 보여야 하고, 외부 공개 HTTP 포트 `8005`는 보이지 않아야 합니다.

## 10. 교육 실습 순서

1. HTTP CPU 모드 실행
2. `/pii/selftest` 호출
3. `/pii/detect`로 주민번호/이메일 탐지 실습
4. `default`와 `strict` 룰셋 차이 확인
5. 자체 서명 인증서 생성
6. HTTPS 전용 모드 실행
7. `curl -k`와 Postman으로 HTTPS 호출
8. HTTPS 전용 패키지 생성
9. 배포 서버에서 패키지 설치 및 실행
10. SSL 오류와 포트 상태 점검
