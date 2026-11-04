# PHP tooling for Patchwarden's migration sandbox (MIGRATION_TOOLS=docker).
# Build it yourself; Patchwarden never pulls images at run time:
#   docker build -t patchwarden/php-tools:1 docker/php-tools
# Multi-arch base images: builds natively on arm64 (Apple silicon, Graviton) and amd64.
FROM php:8.4-cli-bookworm

COPY --from=composer:2.8 /usr/bin/composer /usr/bin/composer

RUN apt-get update \
 && apt-get install -y --no-install-recommends unzip git \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir /tools \
 && cd /tools \
 && COMPOSER_HOME=/tmp/composer composer require --no-interaction --no-progress \
      "rector/rector:^2.0" "phpstan/phpstan:^2.0" \
 && rm -rf /tmp/composer

# The sandbox runs it as nobody, with no network and a read-only root.
USER 65534:65534
WORKDIR /app
