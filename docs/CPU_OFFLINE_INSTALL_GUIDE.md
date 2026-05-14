# XCN PII CPU Offline Install Guide

이 문서는 `xcn-pii-full` CPU 배포 패키지를 신규 Linux 서버에 설치하는 절차서입니다.

## 1. 배포 패키지

패키지 생성 파일 형식:

```bash
dist/xcn-pii-<mode>-package-<version>-<timestamp>.tar.gz
```

예:

```bash
/data01/xcn-pii-full/dist/xcn-pii-all-cpu-package-1.0.0-20260430-120000.tar.gz
```

지원 mode:

- `http-cpu`: HTTP/FastAPI API만 포함
- `grpc-cpu`: gRPC API와 HAProxy LB 포함
- `all-cpu`: HTTP API와 gRPC API를 함께 포함

패키지에는 다음 항목이 포함됩니다.

- Docker 이미지 tar: PII API CPU 이미지, 필요 시 HAProxy/nginx 이미지
- Docker Compose 파일
- `.env.package`
- 시작/종료 스크립트: `start.sh`, `stop.sh`, `scripts/start-*.sh`, `scripts/stop-*.sh`
- 설치 스크립트: `install.sh`
- gRPC LB 설정: `infra/haproxy/grpc-lb.cfg`
- HTTPS 포함 패키지일 경우 nginx HTTPS 설정과 인증서 생성 스크립트
- HuggingFace 모델 캐시: `model-cache/hf-cache.tar.gz`

패키지에는 운영 인증서나 외부 시크릿을 기본 포함하지 않습니다. HTTPS 운영 인증서는 설치 후 `certs/tls.crt`, `certs/tls.key`로 배치합니다.

완전 오프라인 설치에서 문맥 필터를 사용하려면 HuggingFace 모델 캐시가 포함되어야 합니다. 압축 해제 후 아래 파일이 있는지 확인합니다.

```bash
model-cache/hf-cache.tar.gz
```

캐시가 필요 없거나 별도 준비할 경우 패키지 생성 시 `--no-hf-cache`를 사용할 수 있습니다.

## 2. 신규 서버 사전 조건

신규 서버에서 아래 명령이 동작해야 합니다.

```bash
docker --version
docker compose version
tar --version
```

필수 조건:

- Linux 서버
- root 또는 Docker 실행 권한이 있는 계정
- Docker Engine 설치
- Docker Compose plugin 설치
- 패키지 압축 해제 및 Docker 이미지 로드를 위한 디스크 여유 공간

참고:

- `setup.py` 실행은 필요 없습니다.
- Python 패키지 설치도 필요 없습니다.
- PII 앱은 이미 빌드된 Docker 이미지로 제공됩니다.
- 오프라인 대상 서버에서는 소스 빌드가 필요하지 않습니다.

## 3. 패키지 전달

빌드 서버에서 생성한 패키지를 신규 서버로 복사합니다.

예:

```bash
scp /data01/xcn-pii-full/dist/xcn-pii-all-cpu-package-1.0.0-20260430-120000.tar.gz root@<NEW_SERVER_IP>:/data01/
```

신규 서버에서 파일 확인:

```bash
cd /data01
ls -lh xcn-pii-all-cpu-package-1.0.0-20260430-120000.tar.gz
```

## 4. 압축 해제

신규 서버에서 실행합니다.

```bash
cd /data01
tar -xzf xcn-pii-all-cpu-package-1.0.0-20260430-120000.tar.gz
cd xcn-pii
```

파일 구조 확인:

```bash
ls -la
ls -lh images/
```

정상 구조 예:

```text
install.sh
start.sh
stop.sh
docker-compose.http-cpu.yml
docker-compose.grpc-cpu.yml
.env.package
images/xcn-pii-all-cpu-images.tar
model-cache/hf-cache.tar.gz
scripts/start-http-cpu.sh
scripts/stop-http-cpu.sh
scripts/start-grpc-cpu.sh
scripts/stop-grpc-cpu.sh
```

## 5. 설치 및 기동

아래 명령 하나로 설치와 기동을 수행합니다.

```bash
./install.sh
```

`install.sh` 수행 내용:

- Docker 이미지 로드
- `.env.package`를 `.env`로 복사
- `logs/` 런타임 디렉터리 생성
- HuggingFace 모델 캐시를 `xcn-pii_hf_cache` Docker volume으로 복원
- `start.sh` 실행
- 패키지 mode에 맞는 PII 컨테이너 기동

컨테이너를 바로 기동하지 않고 준비만 하려면:

```bash
./install.sh --no-start
```

이후 수동 기동:

```bash
./start.sh
```

## 6. 설치 확인

컨테이너 상태 확인:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

HTTP compose 상태:

```bash
docker compose -f docker-compose.http-cpu.yml --profile http ps
```

gRPC compose 상태:

```bash
docker compose -f docker-compose.grpc-cpu.yml --profile grpc ps
```

HTTP API가 포함된 패키지라면:

```bash
curl -s http://localhost:8005/pii/selftest
```

파일 탐지 API 확인:

```bash
curl -X POST "http://localhost:8005/pii/detect/file" \
  -H "X-PII-RULESET: default" \
  -F "file=@./sample.txt" \
  -F "max_results_per_type=500"
```

gRPC API가 포함된 패키지라면:

```bash
grpcurl -plaintext localhost:50055 xcn.pii.v1.PiiDetector/Health
```

gRPC detect 예:

```bash
grpcurl -plaintext \
  -d '{
    "text": "홍길동 주민번호는 900101-1234567 입니다.",
    "max_results_per_type": 100,
    "ruleset": "default"
  }' \
  localhost:50055 xcn.pii.v1.PiiDetector/Detect
```

## 7. 포트와 기본 설정

기본 포트:

| 서비스 | 기본 외부 포트 | 설명 |
| --- | ---: | --- |
| HTTP API | `8005` | `/pii/detect`, `/pii/detect/file`, `/pii/selftest` |
| HTTPS proxy | `28443` | HTTPS 포함 패키지에서 사용 |
| gRPC LB | `50055` | HAProxy LB endpoint |

주요 `.env` 값:

```bash
PII_IMAGE_REPO=xcn-pii
PII_IMAGE_TAG=1.0.0
PII_GRPC_SCALE=3
PII_RULESET=default
PII_HTTP_MAX_UPLOAD_MB=100
PII_MODEL_PRELOAD_ENABLED=true
PII_LOG_LEVEL=INFO
```

설정을 변경하려면 `.env` 수정 후 재기동합니다.

```bash
vi .env
./stop.sh
./start.sh
```

## 8. 중지 및 재기동

패키지 기본 mode 중지:

```bash
./stop.sh
```

패키지 기본 mode 재기동:

```bash
./start.sh
```

HTTP만 별도 기동/중지:

```bash
./scripts/start-http-cpu.sh
./scripts/stop-http-cpu.sh
```

gRPC만 별도 기동/중지:

```bash
./scripts/start-grpc-cpu.sh
./scripts/stop-grpc-cpu.sh
```

`all-cpu` 패키지에서 전체 기동/중지:

```bash
./scripts/start-all-cpu.sh
./scripts/stop-all-cpu.sh
```

로그 확인:

```bash
docker compose -f docker-compose.http-cpu.yml --profile http logs -f --tail=200
docker compose -f docker-compose.grpc-cpu.yml --profile grpc logs -f --tail=200
docker logs -f xcn-pii-api
docker logs -f xcn-pii-grpc-lb
```

## 9. 런타임 데이터 위치

설치 디렉터리 기준으로 아래 경로에 런타임 파일이 생성됩니다.

```text
logs/
certs/
```

모델 캐시는 Docker volume에 복원됩니다.

```bash
docker volume inspect xcn-pii_hf_cache
```

로그 파일은 기본적으로 컨테이너 내부 `/logs`와 호스트 `./logs`에 기록됩니다.

## 10. HTTPS 운영

HTTPS 포함 패키지는 `docker-compose.https.yml`과 nginx 설정을 포함합니다. HTTPS 전용 패키지는 추가로 `docker-compose.https-only.yml`을 포함하며 HTTP 외부 포트를 publish하지 않습니다.

운영 인증서를 사용할 경우 아래 파일명으로 배치합니다.

```text
certs/tls.crt
certs/tls.key
```

자체 서명 인증서가 필요하면:

```bash
./scripts/make_self_signed_cert.sh localhost
./scripts/make_self_signed_cert.sh pii.example.com 3650
```

HTTPS 확인:

```bash
curl -k https://localhost:28443/pii/selftest
```

## 11. 재설치

같은 서버에서 재설치할 때 기존 컨테이너를 먼저 중지합니다.

```bash
cd /data01/xcn-pii
./stop.sh
```

압축을 새 위치에 다시 풀고 설치합니다.

```bash
cd /data01
tar -xzf xcn-pii-all-cpu-package-1.0.0-20260430-120000.tar.gz
cd xcn-pii
./install.sh
```

기존 `.env`, `certs/`, `logs/`를 유지해야 하면 기존 설치 디렉터리에서 새 설치 디렉터리로 복사합니다.

```bash
cp -a /old/install/path/.env /new/install/path/.env
cp -a /old/install/path/certs /new/install/path/certs
```

## 12. 폐쇄망 런타임 패치

기준 이미지가 이미 폐쇄망 서버에 로드되어 있고 변경 파일이 `.so`, `VERSION`, `app/rules`, `app/static`, `app/proto`, `bin` 같은 런타임 파일에 한정되면 전체 패키지 대신 패치 번들만 전달할 수 있습니다.

외부 빌드 서버에서 기준 이미지 기준 manifest를 생성합니다.

```bash
cd /data01/xcn-pii-full
python tools/build_runtime_manifest.py \
  --from-image xcn-pii/api-http-cpu:1.0.0 \
  --profile http-cpu \
  --version 1.0.0 \
  --require-so \
  --output dist/manifests/base-http-cpu-1.0.0.json
```

변경 버전 이미지에서 패치 번들을 생성합니다.

```bash
python tools/build_patch_bundle.py \
  --profile http-cpu \
  --from-image xcn-pii/api-http-cpu:1.0.1-patch1 \
  --version 1.0.1-patch1 \
  --base-image xcn-pii/api-http-cpu:1.0.0 \
  --target-image xcn-pii/api-http-cpu:1.0.1-patch1 \
  --base-manifest dist/manifests/base-http-cpu-1.0.0.json
```

폐쇄망 서버에서는 기준 이미지가 있는 상태에서 새 이미지 레이어를 만듭니다.

```bash
tar -xzf patch-http-cpu-1.0.1-patch1.tar.gz
./patch-http-cpu-1.0.1-patch1/build_patched_image.sh \
  ./patch-http-cpu-1.0.1-patch1 \
  xcn-pii/api-http-cpu:1.0.0 \
  xcn-pii/api-http-cpu:1.0.1-patch1
```

이후 `.env`의 `PII_IMAGE_TAG`를 새 태그로 바꾸고 재기동합니다.

```bash
PII_IMAGE_TAG=1.0.1-patch1
./stop.sh
./start.sh
```

`requirements*.txt`, Python 버전, OS 패키지, Cython ABI, torch/semantic dependency가 바뀐 경우에는 패치 번들이 아니라 전체 CPU 배포 패키지를 다시 만들어야 합니다.

## 13. 문제 대응

Docker 권한 오류:

```bash
docker ps
```

위 명령이 실패하면 root 계정으로 실행하거나 Docker 권한을 부여해야 합니다.

Compose plugin 없음:

```bash
docker compose version
```

실패하면 Docker Compose plugin을 설치해야 합니다.

포트 충돌:

```bash
ss -lntp | grep -E ':8005|:50055|:28443'
```

이미 사용 중이면 해당 포트를 쓰는 프로세스를 중지하거나 compose 파일의 port mapping을 변경합니다.

이미지 로드 실패:

```bash
ls -lh images/
df -h
```

이미지 tar가 없거나 디스크 공간이 부족한지 확인합니다.

모델 캐시 복원 실패:

```bash
ls -lh model-cache/
docker volume inspect xcn-pii_hf_cache
```

`model-cache/hf-cache.tar.gz`가 없으면 패키지 생성 시 `--no-hf-cache`로 만든 패키지인지 확인합니다. 문맥 필터를 오프라인에서 사용하려면 모델 캐시 포함 패키지를 다시 만들어야 합니다.

컨테이너가 기동되지 않음:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
docker compose -f docker-compose.http-cpu.yml --profile http logs --tail=300
docker compose -f docker-compose.grpc-cpu.yml --profile grpc logs --tail=300
```

HTTP API 오류:

```bash
docker compose -f docker-compose.http-cpu.yml --profile http logs --tail=300 api
curl -i http://localhost:8005/pii/selftest
```

gRPC API 오류:

```bash
docker compose -f docker-compose.grpc-cpu.yml --profile grpc logs --tail=300 api-grpc
docker logs --tail=300 xcn-pii-grpc-lb
```

## 14. 패키지 재생성

빌드 서버에서 패키지를 다시 만들 때:

```bash
cd /data01/xcn-pii-full
./scripts/start_http_cpu.sh
./scripts/start_grpc_cpu_lb_3.sh
./scripts/package_deploy_bundle.sh --mode all-cpu --output-dir ./dist
```

HTTP CPU만:

```bash
./scripts/start_http_cpu.sh
./scripts/package_deploy_bundle.sh --mode http-cpu --output-dir ./dist
```

gRPC CPU만:

```bash
./scripts/start_grpc_cpu_lb_3.sh
./scripts/package_deploy_bundle.sh --mode grpc-cpu --output-dir ./dist
```

HTTPS 포함:

```bash
./scripts/package_deploy_bundle.sh --mode http-cpu --include-https --output-dir ./dist
```

HTTPS 전용:

```bash
./scripts/package_http_cpu_https_only.sh --output-dir ./dist
```

문맥 모델 캐시 제외:

```bash
./scripts/package_deploy_bundle.sh --mode all-cpu --no-hf-cache --output-dir ./dist
```

앱 Docker 이미지는 `VERSION` 파일 값을 태그로 사용합니다. `VERSION=1.0.0`이면 번들 내부 이미지와 `.env.package`는 `xcn-pii/*:1.0.0`을 기준으로 생성됩니다.

기본적으로 `xcn-pii_hf_cache` Docker volume의 HuggingFace 모델 캐시가 포함됩니다. 캐시가 없으면 패키징이 실패하므로, 운영 서버에서 CPU 서비스를 한 번 기동하고 문맥 필터가 동작하는 탐지 요청을 실행해 모델 다운로드/초기화를 완료한 뒤 다시 실행합니다.

생성된 파일:

```bash
dist/xcn-pii-<mode>-package-<version>-<timestamp>.tar.gz
```

압축 내부 최상위 폴더명은 항상 `xcn-pii`입니다.
