FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi uvicorn

WORKDIR /app
COPY services/mock-providers/server.py .

RUN mkdir -p /repos /fixtures

EXPOSE 8100

CMD ["python", "server.py"]
