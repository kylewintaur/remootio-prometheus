FROM golang:1.16-alpine

ENV listenPort=2112
ENV remootioIP=x.x.x.x:8080
ENV scrapeInterval=30

WORKDIR /app

COPY * /app/

RUN go mod download
RUN go build -o /garage-prom

EXPOSE $listenPort

CMD [ "/garage-prom" ]
