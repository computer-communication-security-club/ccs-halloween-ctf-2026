FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY landing.html ./
RUN CGO_ENABLED=0 go build -o /backend .

FROM debian:bookworm-slim
COPY --from=build /backend /backend
EXPOSE 8080
ENTRYPOINT ["/backend"]
