# 추가 민감정보 우회 방어 기준

## 1. 적용 범위

이 문서는 `OTP`, `API_KEY`, `AUTH_TOKEN`, `PASSWORD`, `INTERNAL_ACCESS`, `PRIVATE_KEY`, `CLOUD_CREDENTIAL`, `CONNECTION_STRING`, `SIGNED_URL`, `MFA_SECRET`, `RECOVERY_CODE`, `SESSION_COOKIE` 탐지의 우회 가능성과 현재 방어 범위를 정리한다.

탐지는 원문을 변경하지 않는다. 우회 문자가 있을 때만 보조 탐지 문자열을 만들고, 탐지 위치는 다시 원문 위치로 변환한다. 따라서 API의 `start`, `end`, `matchString`과 요청 로그 redaction은 실제 입력 문자열 전체를 가리킨다.

## 2. 보완된 우회 방식

| 우회 방식 | 예시 | 처리 방식 | 비용 기준 |
| --- | --- | --- | --- |
| zero-width·방향제어 문자 | `API_​KEY`, `Be​arer` | Unicode format 문자를 보조 탐지 문자열에서 제거 | 트리거가 있을 때만 1회 수행 |
| 전각 문자 | `ＡＰＩ＿ＫＥＹ＝...`, `１０．２０．３０．４０` | 문자별 NFKC 정규화 | 트리거가 있을 때만 수행 |
| Unicode 유사 구두점 | 전각 `：／＝`, Unicode dash·slash·quote | ASCII 구두점으로 제한 변환 | 문자표 기반 O(n) |
| JSON/C escape | `API\u005fKEY\u003d...`, `API\x5fKEY` | 유효한 `\u`, `\U`, `\x` 시퀀스만 디코딩 | escape 트리거가 있을 때만 수행 |
| HTML 숫자 엔터티 | `password&#x3d;...` | 10진수·16진수 숫자 엔터티 디코딩 | entity 트리거가 있을 때만 수행 |
| percent encoding | `AUTH_TOKEN%20...`, `%41%50%49` | 연속 `%HH` 바이트를 UTF-8/ASCII로 제한 디코딩 | percent 트리거가 있을 때만 수행 |
| 구분자 제거·변경 | 공백, 1회 개행, `|`, `->`, `=>` | 강한 라벨 뒤 최대 8자의 bounded separator 허용 | 강한 라벨 prefilter 후 실행 |
| Markdown 감싸기 | `**API_KEY** \`value\`` | 라벨·값 주변 Markdown wrapper 최대 3자 허용 | 해당 규칙 내부에서만 처리 |
| OTP 숫자 분할 | `OTP 1 2 3 4 5 6`, `인증번호 | 1&2&3&4&5&6` | 4~8자리 숫자와 제한 구분자를 복원 검증 | OTP 문맥이 있을 때만 실행 |
| MFA seed 그룹화 | `TOTP_SECRET JBSW Y3DP EHPK 3PXP` | 공백·하이픈 제거 후 Base32 구조 검증 | MFA 라벨 prefilter 후 실행 |
| 복구코드 그룹화 | `RECOVERY_CODE ABCD EF12 IJKL 3456` | 그룹 구분자를 허용하고 코드 구조 검증 | 숫자 포함 조건으로 설명 문장 제외 |
| 공급자 토큰 분할 | `AKIA IOSF...`, `A K I A ...`, `ghp_...-...` | AWS/GitHub 고정 형식만 원문 범위로 복원 | 고정 접두가 있을 때만 수행 |
| Base64 | Base64 주민번호·AWS 키 | `decode`/`디코딩` 문맥에서 1회만 디코딩 후 구조·체크섬 검증 | 후보 32개, 252자 이하 |
| 역순 | 역순 주민번호·AWS 키 | `뒤집기`/`역순`/`reverse` 문맥에서만 복원 검증 | 고정 형식만 수행 |
| 숫자형 개인정보 분리 | Unicode dash, `%2D`, `~ : , # --`, 전각공백·NBSP, 임의 숫자 그룹, 코드/JSON 필드 분리 | 주민번호 체크섬과 가까운 주민번호 라벨을 함께 검증 | 약한 구분자·그룹 공백은 강한 라벨 주변에서만 수행 |
| 이메일 동형문자 | `kdhong@хcurenet.com` | 키릴 문자 일부를 skeleton으로 비교한 뒤 이메일 구조 검증 | `@`와 키릴 문자가 모두 있을 때만 수행 |

## 3. 강한 라벨과 과탐 방지

구분자 없는 공백·개행은 다음처럼 값임이 명확한 라벨에만 적용한다.

- API Key: `API_KEY`, `API Key`, `x-api-key`, `Ocp-Apim-Subscription-Key`, `API 키`
- 인증토큰: `AUTH_TOKEN`, `ACCESS_TOKEN`, `REFRESH_TOKEN`, `X_AUTH_TOKEN`, `SESSION_TOKEN`, `CSRF_TOKEN`과 명확한 한국어 토큰 라벨
- 비밀번호: 대문자 환경변수형 `PASSWORD`, `PASSWD`, `DB_PASSWORD`, `ADMIN_PASSWORD`, `ROOT_PASSWORD` 등
- 공급자 자격증명: AWS·Azure의 고정 환경변수명
- MFA·복구코드·세션: 고정 seed, recovery, framework cookie 라벨

다음 방어 조건은 유지한다.

- API Key·토큰은 최소 길이, entropy, 문자 종류를 검증한다.
- 공백-only 비밀번호·세션토큰은 문자 종류가 2개 이상이어야 한다.
- 공백-only 복구코드는 숫자를 최소 한 자리 포함해야 한다.
- `service key <값>`, `recovery code documentation`, `PASSWORD POLICY`, `JSESSIONID documentation` 같은 설명 문장은 탐지하지 않는다.
- 보조 탐지 문자열은 판정에만 사용하고 원문의 반환값과 redaction 범위는 그대로 보존한다.

## 4. 현재 의도적으로 자동 복원하지 않는 방식

다음 방식은 비용·과탐·의미 모호성 때문에 현재 단계에서 자동 복원하지 않는다.

| 미지원 우회 | 이유 | 권장 상위 계층 대응 |
| --- | --- | --- |
| 문맥 없는 전체 요청 Base64·hex·압축·암호화 | 모든 문자열 디코딩은 비용과 과탐이 크고 암호화는 키 없이 복원 불가 | 게이트웨이에서 허용 인코딩 제한, 파일 검사 계층 분리 |
| 형식·필드명이 없는 임의 문자열 연결 | `"abc" + "DEF" + ...`는 코드와 실제 값 구분이 어려움 | 코드 AST/언어별 scanner 사용 |
| 일반 단어 전체의 그리스·키릴 homoglyph | 전 문자를 Latin으로 강제 변환하면 일반 문서 과탐 증가 | 이메일처럼 구조가 강한 타입만 제한 지원 |
| 값 전체의 임의 공백 분할 | 일반 문장과 고entropy 값을 구분하기 어려움 | 강한 라벨·형식별 규칙을 점진 추가 |
| 역순·전치·치환암호 | 가능한 변환 조합이 무한하고 계산량이 큼 | 행위 기반 정책·모델 보조 판정 |
| 여러 요청에 걸친 분할 | 단일 요청 detector에는 세션 상태가 없음 | 게이트웨이 세션 상관분석 |
| 이미지·OCR 내부 문자열 | 현재 API 입력은 텍스트 기준 | OCR 후 텍스트를 본 detector에 전달 |

## 5. 자동 검증

우회 방어 자동 테스트는 `app/test_sensitive_obfuscation.py`와 `app/test_xgen_evasion_hardening.py`에 있다.

```bash
python -m pytest -q app/test_sensitive_obfuscation.py
python -m pytest -q app/test_xgen_evasion_hardening.py
python -m pytest -q
```

성능 검증은 일반 텍스트, 설정형 텍스트, 우회 트리거 포함 텍스트를 분리해 측정한다. 일반 텍스트에서는 정규식 trigger search만 추가되고, Unicode/escape 복원과 두 번째 민감정보 스캔은 실행하지 않는다.

2026-08-28 로컬 검증 결과는 전체 회귀 `483 passed`, 제공된 두 XLSX의 엔진 적용 가능 사례 `300/300` 통과다. 우회 후처리 단독 비용(10만 자, 31회)은 일반 문서 중앙값 `4.476ms`, 숫자 다량 문서 `4.324ms`, 우회 단서 포함 문서 `9.979ms`였다.

제공 XLSX 재검증:

```bash
python scripts/verify_xgen_workbooks.py \
  --evasion-xlsx "X-GEN AI TestCase_변형우회.xlsx" \
  --credential-xlsx "X-GEN AI TestCase_인증정보.xlsx"
```
