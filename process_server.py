import socket
import pickle

HOST = '192.168.1.26'
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print('Loading...')

client_socket, client_address = server_socket.accept()
print('Connected from: ', client_address)

client_socket.sendall(b"get_process_list")

received_data = b""
while True:
    chunk = client_socket.recv(4096)
    if not chunk:
        break
    received_data += chunk

process_list = pickle.loads(received_data)

for process in process_list:
    print(process)

client_socket.close()
