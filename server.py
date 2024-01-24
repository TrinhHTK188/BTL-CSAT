import socket
import pickle
import threading

HOST = '192.168.1.17'
PORT = 12345


def handle_client(client_socket):
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


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print('Server started. Listening for connections...')

    while True:
        client_socket, client_address = server_socket.accept()
        print('Connected from:', client_address)

        client_thread = threading.Thread(
            target=handle_client, args=(client_socket,))
        client_thread.start()


start_server()
