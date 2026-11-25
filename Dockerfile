FROM node:25-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS frontend
WORKDIR /ui
ENV NODE_OPTIONS=--max-old-space-size=256
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY backend /app/backend
RUN pip install --no-cache-dir --require-hashes -r /app/backend/requirements-build.lock -r /app/backend/requirements.lock && pip install --no-cache-dir --no-build-isolation --no-deps /app/backend && useradd --create-home --uid 10001 vulnrelay && mkdir /app/data && chown vulnrelay:vulnrelay /app/data
COPY --from=frontend /ui/dist /app/frontend/dist
ENV VULNRELAY_UI_DIR=/app/frontend/dist PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER vulnrelay
EXPOSE 8080
CMD ["sh", "-c", "vulnrelay init && exec uvicorn vulnrelay.api:app --host 0.0.0.0 --port 8080"]
