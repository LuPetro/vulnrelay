FROM python:3.12-slim
WORKDIR /app
COPY backend /app/backend
RUN pip install --no-cache-dir /app/backend && useradd --create-home --uid 10001 vulnrelay && mkdir /app/data && chown vulnrelay:vulnrelay /app/data
USER vulnrelay
EXPOSE 8080
CMD ["sh", "-c", "alembic -c /app/backend/alembic.ini upgrade head && exec uvicorn vulnrelay.api:app --host 0.0.0.0 --port 8080"]
