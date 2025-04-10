FROM python:3.13-alpine

WORKDIR /usr/src/app

COPY mamapi.py .

RUN apk add --no-cache python3 py3-pip ca-certificates

RUN pip install --no-cache-dir requests

ENTRYPOINT ["python", "mamapi.py"]

CMD []