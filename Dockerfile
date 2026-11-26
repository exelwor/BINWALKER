FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BINWALKER_DB=/data/binwalker.db
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[server]" \
 && useradd --create-home --uid 10001 app \
 && mkdir /data && chown app /data

USER app
VOLUME /data
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
CMD ["uvicorn", "binwalker.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
