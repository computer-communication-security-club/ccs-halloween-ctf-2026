# syntax=docker/dockerfile:1
# PHPossessed — pure PHP2Shell (CVE-2026-109618 / CVE-2026-109619) on
# Apache mod_php, the disclosed surface the public exploits target.
#
# !! VULNERABLE RUNTIME ON PURPOSE !!
# php:8.4.26-apache predates the 2026-10-21 PHP security release
# (8.4.27 fixed PHP2Shell). Do not "helpfully" bump this tag.
#   manifest list  sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a
#   amd64 image    sha256:b0ae0e0d4a3b7f0e800017482752b94f58ab049f2d7fcd108e5452afce3f50d1
FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a AS app

# Stock production configuration, unchanged: display_errors=Off,
# memory_limit=128M, post_max_size=8M, session.upload_progress at defaults.
# Nothing hardened, nothing custom — the runtime IS the vulnerability.
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini

# Apache: listen on 8080 (the container runs as a non-root user), enable the
# rewrite module for the app's pretty routes, send logs to the container's
# stdio so the read-only root fs never needs a writable log dir.
RUN sed -ri 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
    && a2enmod rewrite \
    && sed -ri -e 's!^(\s*ErrorLog)\s+\S+!\1 /proc/self/fd/2!' \
               -e 's!^(\s*CustomLog)\s+\S+!\1 /proc/self/fd/1!' \
               /etc/apache2/apache2.conf

# One prefork child: PHP2Shell is a cross-request bug, so every request must
# land in the same process. Serializing the queue also keeps competing
# solvers from racing each other's dangle windows.
COPY src/apache/single-worker.conf /etc/apache2/conf-enabled/zz-single-worker.conf
COPY src/apache/site.conf /etc/apache2/sites-available/000-default.conf

COPY src/www/ /var/www/html/

# Root-owned, world-readable, unwritable by the app. Read it once you own the
# worker.
COPY flag.txt /flag.txt
RUN chmod 0444 /flag.txt

WORKDIR /var/www/html
EXPOSE 8080
# health.txt is a static file: the health probe never enters the PHP worker,
# so it cannot reset the cross-request state the challenge runs on.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["php", "-r", "exit(strpos((string) @file_get_contents('http://127.0.0.1:8080/health.txt'), 'ok') === false ? 1 : 0);"]

# Black-box web challenge: no player handout, so the dist stage exports nothing.
FROM scratch AS dist
