FROM python:3.11-slim AS builder

ARG INSTALL_SEMANTIC=true

WORKDIR /app

COPY VERSION /app/VERSION
COPY bin /app/bin
COPY setup.py /app/setup.py

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates build-essential \
 && rm -rf /var/lib/apt/lists/* \
 && chmod +x /app/bin/xutf_8

COPY requirements-base.txt requirements-http.txt requirements-semantic.txt ./
RUN pip install --no-cache-dir -r requirements-base.txt -r requirements-http.txt \
 && if [ "$INSTALL_SEMANTIC" = "true" ]; then pip install --no-cache-dir -r requirements-semantic.txt; fi \
 && pip install --no-cache-dir Cython

COPY app ./app
RUN python setup.py build_ext --inplace \
 && find /app/app -type f -name '*.py' \
      ! -name '__init__.py' \
      ! -name 'main.py' \
      ! -name 'grpc_server.py' \
      ! -name 'context_debug_api.py' \
      ! -name 'detection_exclusions.py' \
      ! -name 'guardrail.py' \
      ! -name 'pii.py' \
      ! -name 'schemas.py' \
      ! -path '/app/app/proto/*' \
      ! -path '/app/app/rules/*' \
      ! -path '/app/app/static/*' \
      -delete \
 && find /app/app -type f -name 'test_*.py' -delete \
 && find /app/app -type f -name '*.c' -delete \
 && find /app/app -type d -name '__pycache__' -prune -exec rm -rf {} + \
 && rm -rf /app/build

FROM python:3.11-slim

ARG INSTALL_SEMANTIC=true

WORKDIR /app

COPY --from=builder /app/VERSION /app/VERSION
COPY --from=builder /app/bin /app/bin
COPY requirements-base.txt requirements-http.txt requirements-semantic.txt ./

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir -r requirements-base.txt -r requirements-http.txt \
 && if [ "$INSTALL_SEMANTIC" = "true" ]; then pip install --no-cache-dir -r requirements-semantic.txt; fi \
 && chmod +x /app/bin/xutf_8

COPY --from=builder /app/app /app/app

EXPOSE 8000
EXPOSE 50051
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
