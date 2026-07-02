# 문맥 탐지 모델 선정 근거

## 1. 결론

XCN-PII의 문맥 탐지는 생성형 LLM이 아니라 BERT 계열의 sentence-transformers embedding 모델을 사용한다.

현재 설정:

| 항목 | 값 |
| --- | --- |
| 설정 파일 | `app/rules/context.yaml` |
| 문맥 방식 | `method: embed` |
| 모델 | `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` |
| 적용 단계 | `post_context` |
| 주요 목적 | 정규식/구조 탐지 후 오탐 후보 제거 |

이 방식은 개인정보 탐지 시스템의 운영 조건인 폐쇄망 운영, 낮은 지연시간, 결과 재현성, 개인정보 원문 보관 최소화, 설명 가능한 판정 근거 제공에 더 적합하다.

본 문서에서 비교하는 LLM은 외부 API형 LLM이 아니라, 폐쇄망 내부에 구축 가능한 sLLM 또는 온프레미스 LLM을 기준으로 한다. 외부 반출 이슈가 없는 sLLM이라도 PII 문맥 후처리 목적에서는 생성형 추론보다 embedding 기반 판정이 운영상 더 적합하다는 점을 설명한다.

## 2. 문맥 탐지가 필요한 이유

정규식과 구조 검증은 번호의 모양을 찾는 데 강하지만, 그 숫자가 실제 개인정보인지 업무상 일반 번호인지까지 항상 구분하지는 못한다.

예:

| 입력 예 | 단순 패턴 관점 | 문맥 관점 |
| --- | --- | --- |
| `주민등록번호: 890512-2054508` | 주민번호 후보 | 개인정보 문맥이 있어 탐지 유지 |
| `문서번호 890512-2054508` | 주민번호 후보 | 문서번호 문맥이므로 제외 가능 |
| `ma so thue 0312345678` | 10자리 숫자 후보 | 베트남 세금번호 문맥이 있어 탐지 유지 |
| `관리번호 0312345678` | 10자리 숫자 후보 | 세금번호 문맥이 없어 제외 가능 |

따라서 XCN-PII는 먼저 정규식/Hyperscan/체크섬으로 후보를 찾고, 이후 문맥 필터가 주변 라벨, 표 헤더, 반복 행, semantic similarity를 조합해 최종 유지 여부를 판단한다.

## 3. LLM이 아니라 BERT 계열 embedding 모델을 사용한 이유

### 3.1 개인정보 원문 처리 최소화

폐쇄망 sLLM을 사용하면 외부 반출 위험은 줄일 수 있다. 그러나 sLLM 방식은 일반적으로 입력 문장을 prompt로 구성해 모델에 전달하고, 모델이 응답을 생성한다. 이 경우 개인정보가 포함된 prompt, 모델 응답, serving access log, 추론 trace, 장애 분석 로그를 어떻게 남기고 삭제할지에 대한 관리 부담이 생긴다.

현재 방식은 입력 문맥을 짧은 window로 잘라 embedding vector를 계산한 뒤, 사전에 정의한 개인정보 라벨 문맥과 유사도를 비교한다. 생성 응답을 만들지 않으며, prompt/response 형태의 대화 기록도 필요하지 않다. 따라서 개인정보 원문이 시스템 내부에서 불필요하게 재가공되거나 장기 보관될 가능성을 낮출 수 있다.

### 3.2 폐쇄망 운영 적합성

운영 환경은 폐쇄망을 전제로 한다. sentence-transformers 모델은 사전에 캐시해 Docker volume 또는 패키지에 포함할 수 있고, `PII_HF_OFFLINE=true`, `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1` 설정으로 외부 네트워크 접근 없이 실행 가능하다.

폐쇄망 sLLM도 구축 자체는 가능하지만, 별도 model serving, 전용 추론 자원 산정, tokenizer/model shard 관리, 동시 요청 제어, cold start, 모델 버전 배포 절차가 필요하다. 반면 현재 embedding 모델은 PII 엔진 프로세스 안에서 바로 로딩할 수 있고, CPU 운영도 가능하며, 배포 패키지에 모델 캐시를 포함해 재현 가능한 운영이 가능하다.

### 3.3 지연시간과 처리량

PII 탐지는 API 요청마다 수행되는 후처리 단계다. 폐쇄망 sLLM이라도 후보별 prompt 생성과 token decoding 비용이 있어 대량 문서, 파일 업로드, gRPC 병렬 호출에서 지연시간이 커질 수 있다.

BERT 계열 embedding 방식은 문장 또는 짧은 snippet을 vector로 인코딩하고 cosine similarity를 계산한다. 생성 단계가 없으므로 처리 시간이 예측 가능하고, 후보가 많은 문서에서도 batch/cache/preload 최적화가 쉽다.

### 3.4 결과 재현성

개인정보 탐지 결과는 운영 감사와 장애 분석에서 같은 입력에 대해 같은 결과가 나와야 한다. sLLM은 temperature를 0으로 낮추고 deterministic decoding을 적용할 수 있지만, prompt 변경, 모델 버전 변경, tokenizer 변경, 추론 엔진 변경, max token 정책 변경에 따라 결과가 달라질 수 있다.

현재 방식은 다음 요소로 판정되므로 재현성이 높다.

- 정규식/체크섬/구조 검증
- 고정 embedding 모델
- 고정 threshold
- 타입별 label pattern
- 표 헤더, 반복 행, 이름+PII 행 등 명시적 규칙

응답에는 `context_score`, `context_score_norm`, `context_hybrid_score`, `context_accept_by`, `context_pass`가 포함될 수 있어 왜 통과했는지도 추적할 수 있다.

### 3.5 설명 가능성과 운영 튜닝

sLLM이 "개인정보로 보인다"라고 답하는 방식은 자연어 설명을 만들 수 있다는 장점이 있지만, 그 답변 자체를 운영 규칙으로 고정하기는 어렵다. 반면 현재 방식은 통과 근거가 분리되어 있다.

| 통과 근거 | 의미 |
| --- | --- |
| `embed` | 개인정보 라벨 문맥과 semantic similarity가 threshold 이상 |
| `hybrid` | label/header/repeat/digit 등 규칙 점수와 semantic score 조합 |
| `hybrid_base` | embedding 정규화 점수와 반복 boost 등 기본 hybrid 점수 통과 |
| `force_phrase` | 등본, 증명서 등 강제 통과 문구 |
| `name_pii_row_repeat` | 이름+번호 형태의 반복 행 |
| `bank_pattern` | 은행/계좌 패턴 근거 |

운영 중 오탐/미탐이 발생하면 `context.yaml`에서 타입별 threshold, label pattern, non-PII phrase, label window를 조정할 수 있다. 즉, 모델을 재학습하지 않아도 운영 정책을 빠르게 반영할 수 있다.

## 4. 다국어 문맥 대응 근거

현재 모델은 multilingual sentence-transformers 모델이므로 한국어, 영어, 베트남어 문맥을 같은 embedding 공간에서 비교할 수 있다.

XCN-PII는 모델만 믿지 않고 타입별 라벨도 함께 둔다.

예:

| 타입 | 문맥 라벨 예 |
| --- | --- |
| `SN` | `주민등록번호`, `주민번호`, `resident registration number` |
| `FN` | `외국인등록번호`, `foreigner registration number`, `alien reg no`, `ARC` |
| `VN_CCCD` | `CCCD`, `căn cước công dân`, `so can cuoc cong dan` |
| `VN_MN` | `số điện thoại`, `so dien thoai`, `sdt`, `mobile number` |
| `VN_TIN` | `mã số thuế`, `ma so thue`, `MST`, `tax code` |
| `VN_SI` | `mã số BHXH`, `ma so BHXH`, `BHYT` |

특히 베트남 `VN_TIN`, `VN_SI`처럼 10자리 숫자만으로는 오탐 위험이 큰 항목은 후보 앞쪽에 라벨이 있는 경우를 중심으로 통과시키도록 설정되어 있다.

## 5. 폐쇄망 sLLM 대비 비교

| 비교 항목 | BERT embedding 방식 | 폐쇄망 sLLM 방식 |
| --- | --- | --- |
| 외부 전송 | 불필요 | 폐쇄망 구축 시 외부 전송은 없음 |
| 원문 처리 | 짧은 문맥 window를 vector화하고 점수 계산 | 개인정보 포함 prompt/response/log 관리 필요 |
| 폐쇄망 운영 | 모델 캐시 포함 가능, 앱 프로세스 내 로딩 가능 | 별도 serving, 전용 추론 자원, 모델 shard 관리 필요 |
| 응답 속도 | 예측 가능, 생성 단계 없음 | token 생성 비용과 queue 지연 가능 |
| 결과 재현성 | threshold/규칙 기반으로 높음 | prompt/model/decoding/serving 정책 영향 가능 |
| 설명 가능성 | score와 `context_accept_by` 제공 | 자연어 설명은 가능하나 정책 근거로 고정하기 어려움 |
| 운영 튜닝 | YAML threshold/label 조정 | prompt 튜닝, 모델 교체, few-shot 관리 필요 가능 |
| 비용 | CPU 운영 가능, 고정 비용 | 전용 serving 자원 비용이 상대적으로 큼 |
| 장애 범위 | PII 엔진 내부 구성요소 | 별도 sLLM serving 장애가 탐지 API에 영향 |

## 6. 적용 방식 요약

처리 흐름:

```text
입력 텍스트
  -> 정규식/Hyperscan 후보 탐지
  -> 체크섬/구조 검증
  -> 전화번호/계좌번호 등 후처리
  -> 문맥 window 추출
  -> BERT 계열 embedding 유사도 계산
  -> label/header/repeat/name-row 규칙 점수와 결합
  -> 최종 탐지 결과 반환
```

이 구조는 sLLM이 단독으로 개인정보 여부를 판정하는 구조가 아니라, 확정적인 구조 검증과 운영 규칙을 먼저 적용하고, 애매한 후보에 대해서만 semantic 문맥 점수를 보조 근거로 사용하는 방식이다.

## 7. sLLM을 사용하지 않는다는 의미

폐쇄망 sLLM이 기술적으로 부적합하다는 의미는 아니다. 다음과 같은 업무에는 sLLM이 유용할 수 있다.

- 탐지 결과에 대한 자연어 설명 생성
- 보안 담당자용 요약 리포트 작성
- 복잡한 비정형 문서의 사후 분석
- 운영자가 확인할 검토 의견 초안 작성

다만 XCN-PII의 현재 문맥 필터는 API 요청 중 실시간으로 후보를 통과/제외하는 후처리 단계다. 이 단계에서는 자연어 생성 능력보다 빠른 판정, 재현성, 낮은 운영 비용, 명확한 threshold 관리가 중요하다. 따라서 실시간 탐지 경로에는 BERT embedding 방식을 사용하고, sLLM은 필요 시 비동기 분석 또는 리포팅 보조 기능으로 분리하는 것이 더 적합하다.

## 8. 한계와 보완 방식

embedding 기반 문맥 탐지도 완전한 의미 이해 모델은 아니다. 다음 한계가 있다.

- 매우 짧은 문맥에서는 semantic score가 충분히 나오지 않을 수 있다.
- 업무별 약어, 내부 양식명, 신규 라벨은 설정에 추가해야 한다.
- 숫자 형식이 많은 업무 문서에서는 타입별 threshold 조정이 필요할 수 있다.

이를 보완하기 위해 XCN-PII는 다음 장치를 함께 사용한다.

- 타입별 `indicator_phrases`
- 타입별 `non_pii_phrases`
- label pattern
- 표 헤더 탐지
- 반복 행 boost
- 이름+PII 행 탐지
- 예외처리 JSON API
- `/debug/context`를 통한 점수와 근거 확인

## 9. 사용자 설명용 요약 문구

XCN-PII는 폐쇄망에 sLLM을 구축할 수 있더라도, 실시간 개인정보 문맥 판정에는 BERT 계열 embedding 모델을 사용한다. sLLM은 자연어 설명 생성에는 장점이 있지만, 실시간 탐지 경로에서는 prompt/response 로그 관리, token 생성 지연, 별도 serving 운영, 모델 및 prompt 변경에 따른 결과 변동성이 부담이 될 수 있다. 반면 embedding 방식은 외부 통신 없이 폐쇄망에서 동작하고, 생성 응답 없이 빠르고 재현 가능한 점수 기반 판정이 가능하며, `context_score`와 `context_accept_by`로 통과 근거를 추적할 수 있다. 따라서 현재 방식은 개인정보 탐지 시스템의 보안성, 운영 안정성, 지연시간, 설명 가능성 요구에 더 적합하다.
