# SentryCove reverse proxy / decision API.
#
#   docker build -t sentrycove .
#   docker run -p 8080:8080 -e SENTRYCOVE_UPSTREAM=http://host.docker.internal:3000 sentrycove
#
# Mount your own policy over /etc/sentrycove/sentrycove.yaml.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/sentrycove
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[server]" \
    && useradd --system --uid 10001 --no-create-home sentrycove
COPY examples/sentrycove.yaml /etc/sentrycove/sentrycove.yaml

ENV SENTRYCOVE_CONFIG=/etc/sentrycove/sentrycove.yaml \
    SENTRYCOVE_HOST=0.0.0.0 \
    SENTRYCOVE_PORT=8080

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('SENTRYCOVE_PORT', '8080') + '/_sentrycove/health', timeout=2)"]

ENTRYPOINT ["sentrycove"]
CMD ["proxy"]
