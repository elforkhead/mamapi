FROM python:3.13-alpine

WORKDIR /usr/src/app

RUN apk add --no-cache ca-certificates tzdata tini && \
    pip install --no-cache-dir requests

COPY mamapi.py .

ENTRYPOINT ["/sbin/tini", "--"]

CMD ["python", "mamapi.py"]
