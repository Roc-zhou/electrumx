import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('120.55.38.33', 5805))
print('socket connected!')
data = {
    "jsonrpc" : "2.0",
    "method" : "",
    "params" : None,
    "id" : 1
}

while True:
    data['method'] = input('rpc-method：')
    data['params'] = input('rpc-params：')
    s.send('{} \r\n'.format(data).encode('utf-8'))

    # 每次最多接收1k字节:
    print(s.recv(1024))