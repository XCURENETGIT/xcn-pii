# XCN-PII Detection Verification Guide

이 문서는 현재 `xcn-pii-full` 설정 기준으로 탐지 동작을 검증할 때 확인해야 하는 항목을 정리한다.

## 1. 적용 기준 파일

현재 탐지 설정의 기준 파일은 다음과 같다.

| 구분 | 파일 |
|---|---|
| default ruleset | `app/rules/_ruleset.yaml` |
| strict ruleset | `app/rules/_ruleset_strict.yaml` |
| 문맥/반복/행 구조 후처리 | `app/rules/context.yaml` |
| 문맥 필터 구현 | `app/pii_engine/context_filters.py` |
| 행 구조/이름형 토큰 판정 | `app/pii_engine/context_helpers.py` |
| 회귀 테스트 | `app/test_name_pii_row_repeat.py` |

## 2. 현재 탐지 대상

default ruleset 기준으로 실제 pipeline에 포함된 탐지 항목은 다음 16개다.

| 키 | 의미 | default 탐지 | strict 탐지 | 문맥 필터 대상 |
|---|---|---:|---:|---:|
| `DN` | 운전면허번호 | O | O | O |
| `SSN` | 해외 SSN | O | O | O |
| `SN` | 주민등록번호 | O | O | O |
| `FN` | 외국인등록번호 | O | O | O |
| `PN` | 여권번호 | O | O | O |
| `EML` | 이메일 | O | O | X |
| `CN` | 카드번호 | O | O | O |
| `MN` | 전화번호/휴대폰번호 | O | O | X |
| `BRN` | 사업자등록번호 | O | O | X |
| `BN` | 계좌번호 | O | O | O |
| `AN` | 주소 | O | O | X |
| `VN_CCCD` | 베트남 시민신분증/개인식별번호 | O | O | O |
| `VN_MN` | 베트남 휴대폰번호 | O | O | O |
| `VN_PN` | 베트남 여권번호 | O | O | O |
| `VN_TIN` | 베트남 세금번호/납세자번호 | O | O | O |
| `VN_SI` | 베트남 사회보험/건강보험 코드 | O | O | O |

다음 파일은 존재하지만 현재 ruleset `steps`에 없으므로 기본 탐지 대상이 아니다.

| 키 | 의미 | 비고 |
|---|---|---|
| `IP` | IP 주소 | `app/rules/ip.yaml` 존재, ruleset 미포함 |

주의:

- `EML`은 문맥 필터 대상은 아니지만 탐지 자체는 켜져 있다.
- `MN`도 문맥 필터 대상은 아니므로 전화번호는 기본 정규식 탐지 결과가 바로 반환된다.
- `strict` ruleset에는 `post_context` 단계가 없으므로 문맥 필터 검증은 default ruleset 기준으로 수행한다.

## 3. 문맥 필터 기준

`app/rules/context.yaml` 기준:

```yaml
context:
  enabled: true
  method: embed
  model_name: sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2
  sim_threshold: 0.55
  window_sentences: 2
  target_keys:
    - SN
    - FN
    - SSN
    - DN
    - PN
    - BRN
    - BN
    - CN
    - VN_CCCD
    - VN_MN
    - VN_PN
    - VN_TIN
    - VN_SI
```

문맥 필터 대상은 `SN`, `FN`, `SSN`, `DN`, `PN`, `BRN`, `BN`, `CN`, `VN_CCCD`, `VN_MN`, `VN_PN`, `VN_TIN`, `VN_SI`이다.

베트남 전용 타입 검증 시에는 다음 라벨을 함께 포함하는 샘플을 사용한다.

| 타입 | 권장 라벨 예시 | 양성 샘플 |
|---|---|---|
| `VN_CCCD` | `CCCD`, `căn cước công dân`, `so can cuoc cong dan` | `CCCD: 001234567890` |
| `VN_MN` | `số điện thoại`, `so dien thoai`, `sdt` | `so dien thoai 098-123-4567` |
| `VN_PN` | `hộ chiếu`, `ho chieu`, `passport` | `ho chieu B12345678` |
| `VN_TIN` | `mã số thuế`, `ma so thue`, `MST` | `ma so thue 0312345678-001` |
| `VN_SI` | `mã số BHXH`, `ma so BHXH`, `BHYT` | `ma so BHXH 0123456789` |

문맥 필터 통과 근거는 응답의 `context_accept_by`로 확인한다.

| 값 | 의미 |
|---|---|
| `embed` | embedding 문맥 점수 기준 통과 |
| `hybrid` | label/header/digit/repeat 등을 합산한 hybrid 점수 통과 |
| `hybrid_base` | embedding 정규화 점수 + 반복 boost 등 기본 hybrid 점수만으로 통과 |
| `force_phrase` | 강제 통과 문구 기준 통과 |
| `repeat_same_match` | 동일 값 반복 기준 통과 |
| `name_pii_row_repeat` | 이름형 토큰 + PII 행 패턴 기준 통과 |
| `bank_pattern` | 은행/계좌 패턴 기준 통과 |

## 4. 반복 행 구조 boost

문맥 단어가 없어도 같은 형태의 행이 연속 반복되면 개인정보 목록일 가능성이 높다고 판단한다.

현재 주요 설정:

```yaml
repeat_boost_enabled: true
repeat_boost_min_count: 2
repeat_boost_unique_min: 1
repeat_boost_weight: 0.35
repeat_boost_require_structure: true
repeat_boost_structure_min_tokens: 2
repeat_boost_require_consecutive: true
repeat_boost_consecutive_min_count: 2
```

행 구조는 대략 다음처럼 추상화한다.

| 원문 토큰 | 구조 |
|---|---|
| `홍길동` | `<TXT>` |
| `011228-4295354` | `<NUMH>` |
| `test@example.com` | `<EML>` |
| `192.168.0.1` | `<IP>` |

예:

```text
이름이아니야 011228-4295354
이름이아니야 960805-6437730
```

두 행 모두 `<TXT> <NUMH>` 구조이므로 반복 구조로 판단한다.

CSV/엑셀 복사 형태를 고려해 구조 판정 시 숫자 토큰 뒤의 다음 문자는 무시한다.

```text
, . ; : ， 。 、
```

따라서 아래 두 케이스는 동일하게 통과해야 한다.

```text
이름이아니야 011228-4295354
이름이아니야 960805-6437730
```

```text
이름이아니야  011228-4295354,
이름이아니야 960805-6437730
```

기대 결과:

- `SN_CNT = 2`
- 각 항목 `context_pass = true`
- 일반적으로 `context_accept_by = hybrid_base`

## 5. 이름형 토큰 + PII 행 판정

이름 자체는 별도 개인정보 타입으로 탐지하지 않는다. 이름처럼 보이는 짧은 한글 토큰은 문맥 없는 PII 후보를 통과시키기 위한 보조 근거로만 사용한다.

현재 주요 설정:

```yaml
name_pii_row_repeat_enabled: true
name_pii_row_repeat_min_count: 2
name_pii_row_repeat_unique_min: 1
name_pii_row_repeat_max_distance_chars: 24
name_pii_row_repeat_require_consecutive: true
```

`SN`은 강한 식별자이므로 타입별 override로 1건도 통과할 수 있다.

```yaml
SN:
  hybrid:
    name_pii_row_repeat_min_count: 1
```

### 이름형 토큰 인정 기준

- 공백/구분자로 분리된 독립 한글 토큰만 인정한다.
- 기본 길이는 2~4자 한글이다.
- `홍길동`, `김철수`, `박영희` 같은 토큰은 이름형 토큰으로 볼 수 있다.
- 긴 한글 문자열 내부 일부는 이름으로 보지 않는다.

탐지되어야 하는 예:

```text
홍길동 890512-2054508
```

기대 결과:

- `SN_CNT = 1`
- `context_accept_by = name_pii_row_repeat`
- `context_pass = true`

탐지되지 않아야 하는 예:

```text
고길동 전광판다고광이건뭐야전광판다고광이건뭐야전광판다고광이건뭐야 890512-2054508
```

기대 결과:

- `SN_CNT` 없음
- 긴 한글 문장 내부 조각을 이름으로 오인하지 않아야 한다.

주의:

- `name_pii_row_repeat_max_distance_chars: 24`는 PII 후보 앞뒤 24자 범위에서 이름형 토큰을 찾는다는 의미다.
- 단, 현재 구현은 독립 토큰만 이름 후보로 인정하므로 긴 한글 문자열 내부 2~4자 조각은 제외한다.

## 6. 검증 API

기본 HTTP API:

```bash
curl -sS -X POST "http://localhost:8005/pii/detect" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "홍길동 890512-2054508",
    "max_results_per_type": 100,
    "include_context_debug": true
  }'
```

HTTPS-only 배포를 사용하는 경우 포트/프로토콜을 운영 설정에 맞춘다.

```bash
curl -k -sS -X POST "https://localhost:28443/pii/detect" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "홍길동 890512-2054508",
    "max_results_per_type": 100,
    "include_context_debug": true
  }'
```

## 7. 필수 검증 시나리오

### 7.1 단일 이름 + 주민등록번호

입력:

```text
홍길동 890512-2054508
```

기대:

```text
SN_CNT = 1
context_accept_by = name_pii_row_repeat
context_pass = true
```

### 7.2 긴 한글 문자열 + 주민등록번호 오탐 방지

입력:

```text
고길동 전광판다고광이건뭐야전광판다고광이건뭐야전광판다고광이건뭐야 890512-2054508
```

기대:

```text
SN 결과 없음
```

### 7.3 반복 행 주민등록번호

입력:

```text
이름이아니야 011228-4295354
이름이아니야 960805-6437730
```

기대:

```text
SN_CNT = 2
context_accept_by = hybrid_base
context_pass = true
```

### 7.4 쉼표 포함 반복 행 주민등록번호

입력:

```text
이름이아니야  011228-4295354,
이름이아니야 960805-6437730
```

기대:

```text
SN_CNT = 2
context_accept_by = hybrid_base
context_pass = true
```

### 7.5 전화번호 반복 행

입력:

```text
홍길동 010-1234-5678
김철수 010-2222-3333
```

기대:

```text
MN_CNT = 2
```

주의:

- `MN`은 현재 문맥 필터 target이 아니므로 `context_accept_by`가 없을 수 있다.

### 7.6 단일 전화번호 행

입력:

```text
홍길동 010-1234-5678
```

기대:

```text
MN_CNT = 1
```

주의:

- `MN`은 문맥 필터 대상이 아니므로 단일 행이어도 정규식 탐지 결과가 반환된다.

### 7.7 이메일 탐지

입력:

```text
이메일은 test@example.com 입니다.
```

기대:

```text
EML_CNT = 1
```

주의:

- `EML`은 문맥 필터 target은 아니지만 탐지 자체는 켜져 있다.

### 7.8 주소/IP 미탐지 확인

입력:

```text
주소는 서울특별시 강남구 테헤란로 123 입니다.
서버 IP는 192.168.0.1 입니다.
```

기대:

```text
AN 결과 없음
IP 결과 없음
```

이유:

- `AN`, `IP` 룰 파일은 있으나 현재 ruleset `steps`에 포함되어 있지 않다.

## 8. 로컬 단위 테스트

로컬 개발 환경에서 다음 테스트를 실행한다.

```bash
py -3 -m pytest app\test_name_pii_row_repeat.py
```

전체 관련 smoke 테스트:

```bash
py -3 -m pytest app\test_name_pii_row_repeat.py app\test_refactor_smoke.py app\test_mn_detection.py
```

문법 확인:

```bash
py -3 -m compileall app
```

Linux 서버:

```bash
python3 -m compileall app
```

서버에 `pytest`가 설치되어 있지 않을 수 있으므로, 운영 서버에서는 API 검증을 우선 수행한다.

## 9. 원격 서버 검증 예시

`10.100.40.52` HTTP CPU 배포 기준:

```bash
cd /data01/xcn-pii-full
docker ps --format '{{.Names}} {{.Status}} {{.Ports}}' | grep xcn-pii-api
```

반복 행 쉼표 케이스:

```bash
cat >/tmp/pii_comma_rows.json <<'JSON'
{
  "text": "이름이아니야  011228-4295354,\n이름이아니야 960805-6437730",
  "max_results_per_type": 100,
  "include_context_debug": true
}
JSON

curl -sS -X POST http://localhost:8005/pii/detect \
  -H 'Content-Type: application/json' \
  -d @/tmp/pii_comma_rows.json
```

정상 단일 이름 + 주민번호 케이스:

```bash
cat >/tmp/pii_single_name_sn.json <<'JSON'
{
  "text": "홍길동 890512-2054508",
  "max_results_per_type": 100,
  "include_context_debug": true
}
JSON

curl -sS -X POST http://localhost:8005/pii/detect \
  -H 'Content-Type: application/json' \
  -d @/tmp/pii_single_name_sn.json
```

긴 한글 문자열 오탐 방지 케이스:

```bash
cat >/tmp/pii_false_name_sn.json <<'JSON'
{
  "text": "고길동 전광판다고광이건뭐야전광판다고광이건뭐야전광판다고광이건뭐야 890512-2054508",
  "max_results_per_type": 100,
  "include_context_debug": true
}
JSON

curl -sS -X POST http://localhost:8005/pii/detect \
  -H 'Content-Type: application/json' \
  -d @/tmp/pii_false_name_sn.json
```

## 10. 운영 확인 포인트

검증 시 다음 필드를 반드시 확인한다.

| 필드 | 확인 내용 |
|---|---|
| `*_CNT` | 타입별 탐지 건수 |
| `matchString` | 실제 탐지 문자열 |
| `isValid` | 주민등록번호 등 검증 결과 |
| `context_method` | `embed` 또는 `keyword` |
| `context_accept_by` | 통과 근거 |
| `context_pass` | 문맥/후처리 통과 여부 |
| `ruleset_name` | 적용 ruleset |
| `ruleset_version` | 룰 버전 해시 |
| `ruleset_updated_at` | 룰 변경 시각 |

특히 반복 행/이름형 토큰 관련 검증에서는 `context_accept_by`를 확인한다.

| 기대 근거 | 의미 |
|---|---|
| `name_pii_row_repeat` | 이름형 토큰 + PII 행으로 통과 |
| `hybrid_base` | 반복 행 구조 boost로 통과 |

## 11. 변경 시 주의사항

- `context.yaml`의 `target_keys`에 `MN`, `EML`을 추가하면 전화번호/이메일도 문맥 필터 영향을 받는다.
- `SN.hybrid.name_pii_row_repeat_min_count`를 `2`로 올리면 `홍길동 890512-2054508` 같은 단일 행은 다시 제외될 수 있다.
- `name_pii_row_repeat_max_distance_chars`를 크게 키우면 이름형 토큰 오탐 가능성이 올라간다.
- 반복 행 구조 판정은 쉼표/마침표 등 trailing punctuation을 무시하지만, 행 구조 자체가 다르면 boost가 적용되지 않을 수 있다.
- `strict` ruleset은 `post_context`가 없으므로 default와 결과가 달라질 수 있다.
