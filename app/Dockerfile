FROM python:3.12-slim

WORKDIR /app

COPY . /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxslt1-dev \
        python3-dev \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip index versions netconf-client 2>/dev/null || true \
    && pip install --no-cache-dir flask lxml ncclient pydantic requests netconf-client \
    && apt-get purge -y --auto-remove gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

CMD ["python3", "main.py"]
