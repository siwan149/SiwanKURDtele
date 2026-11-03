FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# MTProto proxy engine (per-user secrets + metrics)
RUN git clone --depth 1 https://github.com/alexbers/mtprotoproxy.git /opt/mtprotoproxy \
    && pip install --no-cache-dir cryptography uvloop

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000 8443

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
