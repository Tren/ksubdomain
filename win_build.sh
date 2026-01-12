#!/bin/bash
# build.sh - 跨平台编译脚本

TARGET=${1:-"linux"}  # 默认编译linux版本

case $TARGET in
    linux)
        echo "正在编译 Linux 版本..."
        export CGO_ENABLED=1
        export GOOS=linux
        export GOARCH=amd64
        export CGO_LDFLAGS="-Wl,-static -L/usr/lib/x86_64-linux-gnu/libpcap.a -lpcap -ldbus-1 -Wl,-Bdynamic"
        OUTPUT="ksubdomain-linux"
        ;;
    windows)
        echo "正在交叉编译 Windows 版本..."
        export CGO_ENABLED=1
        export GOOS=windows
        export GOARCH=amd64
        export CC=x86_64-w64-mingw32-gcc
        export CGO_LDFLAGS="-L/usr/x86_64-w64-mingw32/lib -lwpcap -lws2_32"
        OUTPUT="ksubdomain.exe"
        ;;
    *)
        echo "用法: $0 [linux|windows]"
        exit 1
        ;;
esac

go build -o ./bin/$OUTPUT ./cmd/ksubdomain/
echo "编译完成: ./bin/$OUTPUT"
