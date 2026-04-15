FROM python:3.13-alpine AS build

RUN apk add --no-cache \
    build-base \
    python3-dev \
    git

WORKDIR /build
COPY . .
RUN pip install --no-cache-dir -r ./requirements.txt --prefix=/install .

FROM python:3.13-alpine

RUN apk add --no-cache \
    libstdc++

COPY --from=build /install /usr/local

RUN adduser -S sigrid
USER sigrid
WORKDIR /home/sigrid

ENTRYPOINT ["report-generator"]
