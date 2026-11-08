# Nur als intern freizugebender Serverbaustein, kein oeffentliches Hosting.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_DATA_DIR=/data \
    APP_SECURE_COOKIES=1
RUN groupadd --gid 10001 arbeitszeit \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin arbeitszeit \
    && mkdir -p /srv/app /data \
    && chown -R 10001:10001 /srv/app /data
WORKDIR /srv/app
COPY --chown=10001:10001 server.py backup.py /srv/app/
USER 10001:10001
EXPOSE 8000
CMD ["python", "server.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
