FROM golang:1.10-alpine3.7
WORKDIR /go/src/github.com/theaaf/radius-server
RUN apk --no-cache add git make
RUN wget https://raw.githubusercontent.com/golang/dep/master/install.sh -O - | sh

COPY Gopkg.lock .
COPY Gopkg.toml .
COPY Makefile .
RUN make vendor

COPY . .
RUN make all

FROM alpine:3.7
WORKDIR /opt/radius-server
COPY --from=0 /go/src/github.com/theaaf/radius-server/radius-server .

ENTRYPOINT ["./radius-server"]
