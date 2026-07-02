# XCN PII CPU Offline Install Guide

이 문서는 `xcn-pii` CPU 전용 배포 패키지를 신규 Linux 서버에 설치하는 절차서입니다.

현재 기준 버전은 `VERSION` 파일 값을 따릅니다. 2026-06-18 기준 최신 배포 패키지 예시는 `1.0.4`입니다.

## 1. 배포 패키지

패키지 생성 파일 형식:

```bash
<output-dir>/xcn-pii-all-cpu-package-<version>-<timestamp>.tar.gz
```

예:

```bash
/data01/xcn-pii-packages/xcn-pii-all-cpu-package-1.0.4-20260618-170928.tar.gz
```

패키지는 단일 `all-cpu` 형식만 사용합니다. `install.sh`는 옵션이 없으면 gRPC 모드로 설치합니다. 단일 패키지 안에서 `install.sh --mode all|http|https|grpc` 옵션으로 HTTP, HTTPS, gRPC 실행 모드를 선택할 수 있습니다. gRPC 모드는 기본적으로 `PII_GRPC_SCALE=3`을 사용해 `api-grpc`를 3 replica로 기동하고 HAProxy LB가 `50055` 포트에서 분산 처리합니다.

패키지에는 다음 항목이 포함됩니다.

- Docker 이미지 tar: HTTP CPU 이미지, gRPC CPU 이미지, HAProxy 이미지, nginx 이미지
- Docker Compose 파일: `docker-compose.yml`
- `.env.package`
- 설치 스크립트: `install.sh`
- gRPC LB 설정: `infra/haproxy/grpc-lb.cfg`
- HTTPS proxy 설정: `infra/nginx/https.conf.template`
- HuggingFace 모델 캐시: `model-cache/hf-cache.tar.gz`
- 패키지 manifest: `MANIFEST.txt`
- 패키지 안내 파일: `README.md`

GPU/CUDA/NVIDIA 관련 런타임은 포함하지 않습니다. 문맥 탐지용 PyTorch도 CPU wheel(`torch==2.3.1+cpu`) 기준으로 빌드합니다.

패키지에는 운영 인증서나 외부 시크릿을 기본 포함하지 않습니다. `install.sh`는 `certs/tls.crt`, `certs/tls.key`가 없으면 자체서명 인증서를 생성합니다. 운영 인증서를 사용하려면 `docker compose up -d` 실행 전에 `certs/tls.crt`, `certs/tls.key`로 배치합니다.

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
scp /data01/xcn-pii-packages/xcn-pii-all-cpu-package-1.0.4-20260618-170928.tar.gz root@<NEW_SERVER_IP>:/data01/
```

신규 서버에서 파일 확인:

```bash
cd /data01
ls -lh xcn-pii-all-cpu-package-1.0.4-20260618-170928.tar.gz
```

## 4. 압축 해제

신규 서버에서 실행합니다.

```bash
cd /data01
tar -xzf xcn-pii-all-cpu-package-1.0.4-20260618-170928.tar.gz
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
docker-compose.yml
.env.package
images/xcn-pii-images.tar
model-cache/hf-cache.tar.gz
infra/haproxy/grpc-lb.cfg
infra/nginx/https.conf.template
MANIFEST.txt
README.md
```

## 5. 설치 및 기동

아래 명령으로 이미지 로드와 런타임 파일 준비를 수행합니다.

```bash
./install.sh --no-start
```

`install.sh` 수행 내용:

- Docker 이미지 로드
- `.env.package`를 `.env`로 복사
- `logs/` 런타임 디렉터리 생성
- HTTPS 인증서가 없으면 자체서명 인증서 생성
- HuggingFace 모델 캐시를 `xcn-pii_hf_cache` Docker volume으로 복원

서비스 기동은 Docker Compose 기본 명령을 사용합니다.

```bash
docker compose up -d
```

참고로 `./install.sh`만 실행하면 gRPC 모드로 준비 후 `docker compose up -d`까지 수행합니다.

단일 패키지에서 모드별 설치:

| 명령 | 실행 서비스 |
| --- | --- |
| `./install.sh --no-start` | gRPC LB 단독, gRPC 3 replica |
| `./install.sh --mode all --no-start` | HTTP + HTTPS + gRPC LB, gRPC 3 replica |
| `./install.sh --mode http --no-start` | HTTP 단독 |
| `./install.sh --mode https --no-start` | HTTPS 단독 |
| `./install.sh --mode grpc --no-start` | gRPC LB 단독, gRPC 3 replica |

`install.sh --mode`는 `.env`에 `COMPOSE_PROFILES`를 기록합니다. 이후 운영 명령은 모든 모드에서 동일합니다.

```bash
docker compose up -d
docker compose down
docker compose ps
docker compose logs -f
```


## 6. 설치 확인

컨테이너 상태 확인:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Compose 상태:

```bash
docker compose ps
```

HTTP API가 포함된 모드라면:

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

gRPC API가 포함된 모드라면:

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
| HTTPS proxy | `28443` | HTTPS REST API |
| gRPC LB | `50055` | HAProxy LB endpoint |

주요 `.env` 값:

```bash
PII_IMAGE_REPO=xcn-pii
PII_IMAGE_TAG=1.0.4
PII_GRPC_SCALE=3
PII_RULESET=default
PII_HTTP_MAX_UPLOAD_MB=100
PII_MODEL_PRELOAD_ENABLED=true
PII_EMBED_DEVICE=cpu
PII_HF_OFFLINE=true
PII_LOG_LEVEL=INFO
```

`PII_GRPC_SCALE` 값을 변경하면 다음 `docker compose up -d` 시 `api-grpc` replica 수가 해당 값으로 적용됩니다. 기본 HAProxy 설정은 3개 backend 기준으로 제공되므로 운영 기본값은 `3` 사용을 권장합니다.

설정을 변경하려면 `.env` 수정 후 재기동합니다.

```bash
vi .env
docker compose down
docker compose up -d
```

## 8. 중지 및 재기동

중지:

```bash
docker compose down
```

재기동:

```bash
docker compose up -d
```

로그 확인:

```bash
docker compose logs -f --tail=200
docker logs -f xcn-pii-api-http
docker logs -f xcn-pii-api-https
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

단일 패키지는 HTTPS proxy를 기본 포함합니다. 자체서명 인증서는 `install.sh`가 자동 생성하며, 운영 인증서를 사용할 경우 `docker compose up -d` 전에 아래 경로에 배치합니다.

운영 인증서를 사용할 경우 아래 파일명으로 배치합니다.

```text
certs/tls.crt
certs/tls.key
```

HTTPS 확인:

```bash
curl -k https://localhost:28443/pii/selftest
```

## 11. 재설치

같은 서버에서 재설치할 때 기존 컨테이너를 먼저 중지합니다.

```bash
cd /data01/xcn-pii
docker compose down
```

압축을 새 위치에 다시 풀고 설치합니다.

```bash
cd /data01
tar -xzf xcn-pii-all-cpu-package-1.0.4-20260618-170928.tar.gz
cd xcn-pii
./install.sh --no-start
docker compose up -d
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
cd /data01/xcn-pii-build-1.0.4
python tools/build_runtime_manifest.py \
  --from-image xcn-pii/api-http-cpu:1.0.4 \
  --profile http-cpu \
  --version 1.0.4 \
  --require-so \
  --output dist/manifests/base-http-cpu-1.0.4.json
```

변경 버전 이미지에서 패치 번들을 생성합니다.

```bash
python tools/build_patch_bundle.py \
  --profile http-cpu \
  --from-image xcn-pii/api-http-cpu:1.0.4-patch1 \
  --version 1.0.4-patch1 \
  --base-image xcn-pii/api-http-cpu:1.0.4 \
  --target-image xcn-pii/api-http-cpu:1.0.4-patch1 \
  --base-manifest dist/manifests/base-http-cpu-1.0.4.json
```

폐쇄망 서버에서는 기준 이미지가 있는 상태에서 새 이미지 레이어를 만듭니다.

```bash
tar -xzf patch-http-cpu-1.0.4-patch1.tar.gz
./patch-http-cpu-1.0.4-patch1/build_patched_image.sh \
  ./patch-http-cpu-1.0.4-patch1 \
  xcn-pii/api-http-cpu:1.0.4 \
  xcn-pii/api-http-cpu:1.0.4-patch1
```

이후 `.env`의 `PII_IMAGE_TAG`를 새 태그로 바꾸고 재기동합니다.

```bash
PII_IMAGE_TAG=1.0.4-patch1
docker compose down
docker compose up -d
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
docker compose logs --tail=300
```

HTTP API 오류:

```bash
docker compose logs --tail=300 api-http
docker compose logs --tail=300 api-https
curl -i http://localhost:8005/pii/selftest
```

gRPC API 오류:

```bash
docker compose logs --tail=300 api-grpc
docker logs --tail=300 xcn-pii-grpc-lb
```

## 14. 패키지 재생성

빌드 서버에서 패키지를 다시 만들 때:

```bash
cd /data01/xcn-pii-build-1.0.4
docker compose -f docker-compose.http-cpu.yml --profile http build api
docker compose -f docker-compose.grpc-cpu.yml --profile grpc build api-grpc
docker pull haproxy:3.1-alpine
docker pull nginx:1.27-alpine
./scripts/package_deploy_bundle.sh --output-dir /data01/xcn-pii-packages
```

문맥 모델 캐시 제외:

```bash
./scripts/package_deploy_bundle.sh --no-hf-cache --output-dir /data01/xcn-pii-packages
```

앱 Docker 이미지는 `VERSION` 파일 값을 태그로 사용합니다. `VERSION=1.0.4`이면 번들 내부 이미지와 `.env.package`는 `xcn-pii/*:1.0.4`를 기준으로 생성됩니다.

기본적으로 `xcn-pii_hf_cache` Docker volume의 HuggingFace 모델 캐시가 포함됩니다. 캐시가 없으면 패키징이 실패하므로, 운영 서버에서 CPU 서비스를 한 번 기동하고 문맥 필터가 동작하는 탐지 요청을 실행해 모델 다운로드/초기화를 완료한 뒤 다시 실행합니다.

생성된 파일:

```bash
<output-dir>/xcn-pii-all-cpu-package-<version>-<timestamp>.tar.gz
```

압축 내부 최상위 폴더명은 항상 `xcn-pii`입니다.

CPU 전용 이미지 검증:

```bash
docker run --rm --entrypoint python xcn-pii/api-http-cpu:1.0.4 \
  -c 'import torch; print(torch.__version__); print(torch.cuda.is_available())'

docker run --rm --entrypoint python xcn-pii/api-http-cpu:1.0.4 \
  -m pip freeze | grep -Ei 'nvidia|cuda|cudnn|cublas|cufft|curand|cusolver|cusparse|nccl|triton' || echo no_gpu_deps
```

정상 기준:

```text
2.3.1+cpu
False
no_gpu_deps
```
