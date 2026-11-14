# SignalMoat reverse proxy / decision API.
#
#   docker build -t signalmoat .
#   docker run -p 8080:8080 -e SIGNALMOAT_UPSTREAM=http://host.docker.internal:3000 signalmoat
#
# Mount your own policy over /etc/signalmoat/signalmoat.yaml.
FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/signalmoat
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[server,redis]" \
    && useradd --system --uid 10001 --no-create-home signalmoat
COPY examples/signalmoat.yaml /etc/signalmoat/signalmoat.yaml

ENV SIGNALMOAT_CONFIG=/etc/signalmoat/signalmoat.yaml \
    SIGNALMOAT_HOST=0.0.0.0 \
    SIGNALMOAT_PORT=8080

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('SIGNALMOAT_PORT', '8080') + '/_signalmoat/health', timeout=2)"]

ENTRYPOINT ["signalmoat"]
CMD ["proxy"]
