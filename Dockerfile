FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=builder /install /usr/local
COPY api ./api
COPY certwatch_cli.py .
ENTRYPOINT ["python", "certwatch_cli.py"]
CMD ["--help"]
