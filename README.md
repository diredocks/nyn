# inyn-go - I am Not Your Node

inyn-go 是新华三 802.1x 认证协议客户端的开源实现。🐳

得益于 Golang 强大的生态和现代工具链，我们除了能更轻松的实现基本的认证功能，还能够实现更多小功能，并在多种平台上运行。

## 特点

- 使用 Golang 构建
- 跨平台
- 支持自定义字典和版本号信息
- 可使用 http 协议交互
- 内建定时认证与下线
- 支持后台服务模式

## 使用

### 命令行调用
```shell
inyn-go -u [username] -p [password] -d [device]
```

### 配置文件
```shell
inyn-go -c [path_to_config]
```
配置文件参考：docs/configuration.md

亦可作为后台服务部署：
```shell
systemctl status inyn-go # Systemd
service status inyn-go # Init.d
```

## 开发

构建参考：docs/build.md  
相关协议细节参考：docs/protocol.md  
字典提取参考：docs/dump_dict.md  

## 致谢
inyn-go 的诞生离不开 njit8021xclient, nxsharp, gopacket 等项目