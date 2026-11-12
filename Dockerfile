FROM node:22-slim AS frontend
WORKDIR /ui
ENV NODE_OPTIONS=--max-old-space-size=256
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY backend /app/backend
RUN pip install --no-cache-dir /app/backend && useradd --create-home --uid 10001 vulnrelay && mkdir /app/data && chown vulnrelay:vulnrelay /app/data
COPY --from=frontend /ui/dist /app/frontend/dist
ENV VULNRELAY_UI_DIR=/app/frontend/dist
USER vulnrelay
EXPOSE 8080
CMD ["sh", "-c", "vulnrelay init && exec uvicorn vulnrelay.api:app --host 0.0.0.0 --port 8080"]
