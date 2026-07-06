FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget dnsutils iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi uvicorn pydantic httpx requests dnspython pyyaml python-dotenv cachetools

COPY ./orchestrator /raphael/orchestrator

ENV PYTHONPATH=/raphael/orchestrator:/raphael
ENV BRAIN_PORT=3700
ENV OPENAI_BASE_URL=http://host.docker.internal:11434/v1

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -s /sbin/nologin -d /nonexistent appuser && \
    chown -R 1000:1000 /raphael

USER 1000:1000

EXPOSE 3700

CMD ["python", "-m", "uvicorn", "brain.api:app", "--host", "0.0.0.0", "--port", "3700"]
