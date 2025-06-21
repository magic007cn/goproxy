# goproxy
一个简单的正向代理服务器,基本靠DeepSeek来编写
编译为Linux版本：
CGO_ENABLED=0  GOOS=linux  GOARCH=amd64  go build -o goproxy_linux
编译为MacOS for X86版本：
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64  go build -o goproxy_macos

