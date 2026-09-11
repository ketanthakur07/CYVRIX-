FROM python:3.9

ENV APP_SECRET=TEST_ONLY_PLACEHOLDER_SECRET
ENV DATABASE_PASSWORD=TEST_ONLY_PLACEHOLDER_DB_PASS

RUN apt-get update && apt-get install -y curl

RUN curl -sSL https://example.com/install.sh | sh

EXPOSE 22
EXPOSE 8080

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["python", "app.py"]
