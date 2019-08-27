#!/usr/bin/env bash
mkdir -p pb
protoc -I$GOPATH/src/github.com/bootapp/protos/core \
       --go_out=plugins=grpc:./pb \
        $GOPATH/src/github.com/bootapp/protos/core/dal_auth.proto