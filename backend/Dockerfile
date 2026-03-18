FROM python:3.11-slim

ARG APP_VERSION=0.02

WORKDIR /app

ENV APP_VERSION=${APP_VERSION}

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

EXPOSE 4001

CMD ["./entrypoint.sh"]
