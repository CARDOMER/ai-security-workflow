FROM node:22-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ENV VITE_PUBLIC_DEMO=1
RUN npm run build

FROM alpine:3.22 AS training
WORKDIR /training
RUN apk add --no-cache git \
    && git init \
    && git fetch --depth 1 https://github.com/TBagirov/training.git fe1fcbe212669783480666b9b60147c8a8c6eef4 \
    && git checkout --detach FETCH_HEAD

FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    AI_SUMMARY_PROVIDER=rules \
    WORKFLOW_PUBLIC_DEMO=1 \
    WORKFLOW_HISTORY_DB=/tmp/cyber-garden-history.sqlite3
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ ./backend/
COPY demo/ ./demo/
COPY --from=training /training/training-project ./test-data/training-project
COPY --from=training /training/vulnerability-database ./test-data/vulnerability-database
COPY --from=frontend /build/dist ./frontend/dist

USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "port=${PORT:-8000}; export WORKFLOW_WEBHOOK_URL=http://127.0.0.1:$port/api/workflow/demo-webhook; exec python -m uvicorn backend.hosted:app --host 0.0.0.0 --port \"$port\""]
