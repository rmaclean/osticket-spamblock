ARG PHP_VERSION=8.3
ARG OSTICKET_VERSION=v1.18.3

FROM php:${PHP_VERSION}-cli-bookworm AS builder
ARG OSTICKET_VERSION

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch ${OSTICKET_VERSION} https://github.com/osTicket/osTicket.git .
RUN php manage.php deploy --setup /deploy

FROM php:${PHP_VERSION}-apache-bookworm

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    libfreetype6-dev \
    libicu-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libzip-dev \
  && docker-php-ext-configure gd --with-freetype --with-jpeg \
  && docker-php-ext-install -j"$(nproc)" \
    gd \
    gettext \
    intl \
    mysqli \
    opcache \
    zip \
  && rm -rf /var/lib/apt/lists/* \
  && a2enmod rewrite headers

COPY --from=builder /deploy/ /var/www/html/
COPY docker/osticket/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
  && chown -R www-data:www-data /var/www/html

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
