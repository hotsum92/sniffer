import socket
import os

# リッスンするホストの IP アドレス
host = "127.0.0.1"
# raw ソケットを作成しパブリックなインタフェースにバインド
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))

# キャプチャー結果に IP ヘッダーを含めるように指定
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Windows の場合は ioctl を使用してプロミスキャスモードを有効化
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# 単一パケットの読み込み
print(sniffer.recvfrom(65565))

# Windows の場合はプロミスキャスモードを無効化
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
