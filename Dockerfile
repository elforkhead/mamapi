FROM python:3.13-alpine

WORKDIR /usr/src/app

RUN apk add --no-cache ca-certificates tzdata

RUN pip install --no-cache-dir requests apprise

COPY mamapi.py .

ENTRYPOINT ["python", "mamapi.py"]
