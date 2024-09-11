# 协议

## Start 包
需要：本机MAC（或任意随机MAC）

构造包：18位，其中前14位为 Ethernet 头，包含广播目的 MAC 地址与本机 MAC（MAC Header），以及 Ethernet Type ，后四位为标准 EAPOL Start 包

效果：在发送 Start 包后，服务器会回应 MAC 地址，于是我们将以后通讯的 MAC 地址改为服务器相应的 MAC 地址，并在之后的通讯中使用该 Ethernet 头

## Response 包
### Availvable
需要：服务器发来的请求包，ip地址，用户名

特征：请求包第 18 位（EAP_CODE）为 REQUEST，第 22 位（EAP_TYPE）为 AVAILABLE

回应：回应一个 EAP_CODE 为 RESPONSE，EAP_TYPE 为 AVAILABLE 的包。

包内容（Body）为

0 0x00 // 是否使用代理
1 0x15 // 上报 IP（无所谓，可以随机生成）
2 0x04 // 上报 IP
3...6  // IP
7 0x06 // 携带版本号
8 0x07 // 携带版本号
9...36 // 加密过后的版本号（28位）
37...38 // 两个空字符

### Indetity
需要：服务器发来的请求包，ip地址，用户名

