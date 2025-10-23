# c2_server.py  
  
import socket  
import threading  
import datetime  
import json  
import random  
  
class C2Server:  
    def __init__(self, host='0.0.0.0', port=8080, log_file='c2_server.log'):  
        self.host = host  
        self.port = port  
        self.clients = []  
        self.commands = ['scan', 'encrypt', 'exfiltrate', 'persist']  
        self.log_file = log_file  
  
    def start_server(self):  
        print(f"[{datetime.datetime.now()}] Starting C2 server on {self.host}:{self.port}")  
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        server.bind((self.host, self.port))  
        server.listen(5)  
        self.log_event('server_start', f"Server started on {self.host}:{self.port}")  
  
        try:  
            while True:  
                client_socket, addr = server.accept()  
                client_id = f"{addr[0]}:{addr[1]}"  
                self.log_event('client_connected', f"Client connected: {client_id}")  
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_id))  
                client_thread.daemon = True  
                client_thread.start()  
        except KeyboardInterrupt:  
            print("\n[!] Shutting down the server.")  
            server.close()  
            self.log_event('server_shutdown', "Server shut down.")  
  
    def handle_client(self, client_socket, client_id):  
        self.clients.append((client_socket, client_id))  
        while True:  
            try:  
                data = client_socket.recv(1024).decode('utf-8')  
                if data:  
                    self.log_event('client_message', f"Received from {client_id}: {data}")  
                    # Send a random command  
                    command = random.choice(self.commands)  
                    client_socket.send(command.encode('utf-8'))  
                    self.log_event('command_sent', f"Sent to {client_id}: {command}")  
                else:  
                    self.log_event('client_disconnected', f"Client disconnected: {client_id}")  
                    client_socket.close()  
                    self.clients.remove((client_socket, client_id))  
                    break  
            except ConnectionResetError:  
                self.log_event('client_disconnected', f"Client disconnected unexpectedly: {client_id}")  
                client_socket.close()  
                self.clients.remove((client_socket, client_id))  
                break  
  
    def log_event(self, event_type, message):  
        timestamp = datetime.datetime.now().isoformat()  
        log_entry = {  
            'timestamp': timestamp,  
            'event_type': event_type,  
            'message': message  
        }  
        print(f"[{timestamp}] [{event_type}] {message}")  
        with open(self.log_file, 'a') as f:  
            f.write(json.dumps(log_entry) + '\n')  
  
if __name__ == "__main__":  
    c2_server = C2Server()  
    c2_server.start_server()  