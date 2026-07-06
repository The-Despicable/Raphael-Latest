FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git ca-certificates whatweb \
    && rm -rf /var/lib/apt/lists/*

RUN curl -Lo /usr/local/bin/subfinder \
    https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64 \
    && chmod +x /usr/local/bin/subfinder

RUN curl -Lo /usr/local/bin/nuclei \
    https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64 \
    && chmod +x /usr/local/bin/nuclei

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

RUN curl -Lo /usr/local/bin/hashcat \
    https://github.com/hashcat/hashcat/releases/latest/download/hashcat-linux-x64 \
    && chmod +x /usr/local/bin/hashcat 2>/dev/null; true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser

USER 1000:1000

EXPOSE 3200

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3200"]
