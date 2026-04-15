# =====================================
# Build stage
# =====================================
FROM python:3.13-alpine AS build

# Do not write .pyc files to disk (keeps image clean and avoids __pycache__)
# Disable stdout/stderr buffering so logs appear immediately (important in Docker)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Build-time dependencies (removed after build):
# - build-base: C/C++ compiler toolchain (required to build numpy, pandas, matplotlib extensions)
# - python3-dev: Python headers needed for compiling C extensions
# - git: required because one dependency is installed directly from a git repository
# - pkgconfig: allows build scripts to locate system libraries (used by matplotlib, pillow, lxml)
# - freetype-dev: headers for FreeType (matplotlib text rendering, pillow)
# - libpng-dev: headers for libpng (matplotlib, pillow image support)
# - libxml2-dev: headers for libxml2 (lxml, python-docx, python-pptx)
RUN apk add --no-cache \
        build-base \
        python3-dev \
        git \
        pkgconfig \
        freetype-dev \
        libpng-dev \
        libxml2-dev

WORKDIR /build

# Copy packaging metadata first (better cache reuse)
COPY pyproject.toml setup.cfg setup.py README.md ./
# Copy only the application source
COPY src/ src/


# Install the application and all dependencies into an isolated prefix
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install .

# =====================================
# Runtime stage
# =====================================
# NOTE:
# This image supports numpy, pandas, matplotlib, pillow, and lxml.
# Removing runtime libraries may cause import errors or rendering failures
# that only appear at runtime (not during build).

FROM python:3.13-alpine

# Do not write .pyc files at runtime
# Disable Python output buffering (required for correct container logging)
# Force matplotlib to use a headless backend (no X11 / GUI probing)
# Store matplotlib font/cache data in a writable temporary directory
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLBACKEND=Agg \
    MPLCONFIGDIR=/tmp/matplotlib

# Runtime-only shared libraries:
# - libstdc++: required by numpy / pandas / matplotlib C++ extensions
# - libgcc: GCC runtime support for compiled extensions
# - freetype: font rendering for matplotlib and pillow
# - libpng: PNG image support for matplotlib and pillow
# - libxml2: XML parsing for lxml, python-docx, python-pptx
# - fontconfig: font discovery for matplotlib
# - ttf-dejavu: default Unicode fonts expected by matplotlib

RUN apk add --no-cache \
        libstdc++ \
        libgcc \
        freetype \
        libpng \
        libxml2 \
        fontconfig \
        ttf-dejavu \
    && adduser -S -h /home/sigrid sigrid

COPY --from=build /install /usr/local

USER sigrid
WORKDIR /home/sigrid

ENTRYPOINT ["report-generator"]
