FROM python:3.13-alpine

COPY ./ /sources/report-generator

RUN apk add --no-cache \
            build-base \
            git \
            graphviz \
            openldap-dev \
            python3-dev \
    && adduser -S sigrid \
    && pip install --no-cache-dir /sources/report-generator \
    && rm -rf /sources

USER sigrid
WORKDIR /home/sigrid

ENTRYPOINT ["report-generator"]
