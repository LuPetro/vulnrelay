FROM node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS frontend
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
