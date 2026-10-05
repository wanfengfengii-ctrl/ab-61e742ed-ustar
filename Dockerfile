FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BUNDLE_HOST=0.0.0.0 \
    BUNDLE_PORT=8080

WORKDIR /srv

COPY app ./app

# Build-time verification: all sources must compile.
RUN python -m compileall -q app && rm -rf app/__pycache__

RUN adduser --system --no-create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import json,os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health'%os.environ.get('BUNDLE_PORT','8080'),timeout=2).read()" || exit 1

CMD ["python", "-m", "app.server"]
