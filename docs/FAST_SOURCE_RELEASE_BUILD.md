# 소스 전용 빠른 릴리스 빌드

## 목적

Python·PyTorch·CUDA와 운영 패키지가 그대로이고 `app/`, `bin/`, `VERSION`만 변경된 경우,
대형 의존성을 다시 설치하지 않고 CPU/GPU의 HTTP·gRPC 이미지를 생성한다.

52번 서버의 영구 작업 경로는 다음과 같다.

```bash
cd /data01/xcn-pii-release-builder
```

## 최초 1회 준비

CPU와 GPU의 마지막 검증 버전이 다를 수 있으므로 각각 지정할 수 있다.

```bash
bash scripts/prepare_source_build_env.sh \
  --profile all \
  --cpu-base-version 1.0.9 \
  --gpu-base-version 1.0.8
```

소스 빌더는 기존 HTTP·gRPC 이미지의 Python/CUDA 의존성을 그대로 사용하고 컴파일러와
Cython만 한 번 추가한다. 기반 이미지 ID와 의존성 지문은 Docker label에 저장된다.

## 소스 변경 후 빌드

```bash
bash scripts/build_source_release.sh \
  --profile all \
  --cpu-base-version 1.0.9 \
  --gpu-base-version 1.0.8 \
  --target-version 1.0.10
```

오프라인 CPU/GPU 패키지까지 생성하려면 다음 옵션을 추가한다.

```bash
  --package \
  --output-dir /data01/xcn-pii-packages \
  --name-suffix final-$(date +%Y%m%d)
```

## 전체 빌드가 필요한 변경

- `requirements-*.txt` 변경
- `Dockerfile.cpu`, `Dockerfile.gpu`의 OS/Python/CUDA 의존성 변경
- HTTP 또는 gRPC 기반 이미지 교체
- Python ABI 변경

이 경우 기존 Dockerfile로 전체 이미지를 검증한 뒤 새 버전을 기준으로
`prepare_source_build_env.sh`를 다시 실행한다. 빠른 빌드 스크립트는 지문이나 이미지 ID가
다르면 실행을 중단해 오래된 의존성 위에 새 소스를 얹지 않는다.

완전한 오프라인 패키지는 이미지와 Hugging Face 캐시를 다시 저장·압축하므로 이미지 생성보다
시간이 더 필요하다. 개발 반복에서는 먼저 이미지만 만들고, 최종 납품 시에만 `--package`를
사용하는 것이 권장된다.

2026-08-14에 52번 서버에서 현재 1.0.9 소스로 측정한 결과는 다음과 같다.

| 작업 | 측정 시간 |
|---|---:|
| CPU/GPU 소스 빌더 재사용 확인 | 0.49초 |
| CPU/GPU HTTP·gRPC 4개 이미지 소스 빌드 및 import 확인 | 21.81초 |

최초 소스 빌더 준비는 CPU와 GPU를 병렬 실행해 각각 약 145~147초가 걸렸으며, 이후 소스
변경에는 반복되지 않는다. 서버 부하와 Docker 캐시 상태에 따라 실제 시간은 달라질 수 있다.
