# FROM golang:1.20-alpine
FROM golang@sha256:76aadd914a29a2ee7a6b0f3389bb2fdb87727291d688e1d972abe6c0fa6f2ee0

RUN apk update && apk upgrade && apk --no-cache add make

WORKDIR /go/src/github.ibm.com/gitsecure-net-top/

COPY pkg/    pkg/
COPY cmd/    cmd/
COPY go.mod go.sum Makefile ./

RUN make

FROM registry.access.redhat.com/ubi8/ubi@sha256:fc88b136e97b4160a74f4a4a8fd50965a286e855ac5a221a4bfdb2c9b765397a
RUN yum -y upgrade

WORKDIR /gitsecure
COPY --from=0 go/src/github.ibm.com/gitsecure-net-top/bin/net-top .

ENTRYPOINT ["/gitsecure/net-top"]
