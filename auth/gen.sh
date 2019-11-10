#!/usr/bin/env bash
mkdir -p pb
protoc -I$GOPATH/src/github.com/bootapp/proto-core \
       --go_out=plugins=grpc:./pb \
        $GOPATH/src/github.com/bootapp/proto-core/core_common.proto \
        $GOPATH/src/github.com/bootapp/proto-core/dal_auth.proto