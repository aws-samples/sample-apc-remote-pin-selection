# Flutter has no image on ECR Public, so the build stage installs a pinned SDK
# release on a Debian base.
FROM public.ecr.aws/docker/library/debian:bookworm-slim AS build
ARG FLUTTER_VERSION=3.44.4
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git unzip xz-utils \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth 1 --branch ${FLUTTER_VERSION} https://github.com/flutter/flutter.git /opt/flutter
ENV PATH=/opt/flutter/bin:${PATH}
RUN flutter config --no-analytics && flutter precache --web

WORKDIR /app
COPY pubspec.yaml pubspec.lock ./
RUN flutter pub get

COPY . .
ARG API_BASE_URL=http://localhost:8080
RUN flutter build web \
    --release \
    --no-web-resources-cdn \
    --dart-define=API_BASE_URL=${API_BASE_URL}

FROM public.ecr.aws/docker/library/httpd:2.4-alpine

RUN sed -i \
      -e 's/^#LoadModule rewrite_module/LoadModule rewrite_module/' \
      -e '/<Directory "\/usr\/local\/apache2\/htdocs">/,/<\/Directory>/s/AllowOverride None/AllowOverride All/' \
      -e '$a Include conf/extra/frontend.conf' \
      /usr/local/apache2/conf/httpd.conf

COPY --from=build /app/build/web/ /usr/local/apache2/htdocs/
COPY apache/.htaccess /usr/local/apache2/htdocs/.htaccess
COPY apache/frontend.conf /usr/local/apache2/conf/extra/frontend.conf

EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
