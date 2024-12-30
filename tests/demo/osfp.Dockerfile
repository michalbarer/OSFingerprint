FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    nmap && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L -o os_fingerprint-0.1.0-py3-none-any.whl \
    https://github.com/michalbarer/OSFingerprint/releases/download/v0.1.0/os_fingerprint-0.1.0-py3-none-any.whl

RUN pip install ./os_fingerprint-0.1.0-py3-none-any.whl

CMD ["bash", "-c", "while true; do sleep 30; done"]
