FROM golang:1.10.3-alpine3.8 AS builder

WORKDIR /go/src/samlidp
COPY . /go/src/samlidp

RUN go install

FROM alpine:3.8

COPY --from=builder /go/bin/samlidp /usr/local/bin/samlidp

EXPOSE 8000

ENTRYPOINT ["samlidp"]