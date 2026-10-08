# Build wheels for the app and its dependencies in a throwaway stage, so the final
# image contains only what's installed.
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBER_ALERT_LOG_FILE=/logs/auth.log \
    CYBER_ALERT_CONFIG=/etc/cyber-alert/cyber-alert.yaml

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels cyber-alert-system \
    && rm -rf /wheels
COPY config/cyber-alert.yaml /etc/cyber-alert/cyber-alert.yaml

# Run unprivileged. Named volumes mounted at /logs and /data inherit this ownership.
RUN useradd --system --uid 10001 --no-create-home cyberalert \
    && mkdir /logs /data \
    && chown cyberalert /logs /data
USER cyberalert
WORKDIR /data

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/summary', timeout=4)"]

# Listening on all interfaces is needed inside a container; compose.yaml publishes
# the port on the host's loopback interface only, since the dashboard has no login.
CMD ["cyber-alert", "serve", "--host", "0.0.0.0", "--db", "/data/cyber-alert.db"]
