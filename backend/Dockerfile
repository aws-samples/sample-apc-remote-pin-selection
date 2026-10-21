# Multi-stage build producing a minimal `scratch` image. The only extra file is
# the public TLS CA bundle, which the AWS SDK needs to verify AWS service
# endpoints. (It is unrelated to the AWS Private CA used for app certificates.)
FROM public.ecr.aws/docker/library/golang:1.24-alpine AS build
ARG GOPROXY=direct
ENV GOPROXY=${GOPROXY}
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o /bin/backend .

FROM scratch
WORKDIR /data
ENV HOME=/root
ENV AWS_SDK_LOAD_CONFIG=1
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /bin/backend /bin/backend
EXPOSE 8080
ENTRYPOINT ["/bin/backend"]
