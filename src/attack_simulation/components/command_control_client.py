# c2_client.py  
  
import socket  
import time  
import datetime  
import json  
import random  
import threading  
  
class C2Client:  
    def __init__(self, server_host='127.0.0.1', server_port=8080, interval=10):  
        self.server_host = server_host  
        self.server_port = server_port  
        self.interval = interval  # Interval between beacon messages  
        self.log_file = f'c2_client_{random.randint(1000,9999)}.log'  
  
    def start_client(self):  
        while True:  
            try:  
                self.connect_to_server()  
                time.sleep(self.interval)  
            except Exception as e:  
                self.log_event('connection_error', f"Connection error: {e}")  
                time.sleep(self.interval)  
  
    def connect_to_server(self):  
        timestamp = datetime.datetime.now().isoformat()  
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        client_socket.connect((self.server_host, self.server_port))  
        client_id = client_socket.getsockname()  
        self.log_event('connected', f"Connected to server from {client_id}")  
  
        try:  
            # Send beacon message  
            beacon_message = f"Beacon from {client_id}"  
            client_socket.send(beacon_message.encode('utf-8'))  
            self.log_event('beacon_sent', beacon_message)  
  
            # Receive command from server  
            command = client_socket.recv(1024).decode('utf-8')  
            self.log_event('command_received', f"Received command: {command}")  
  
            # Simulate executing the command  
            execution_result = self.execute_command(command)  
            client_socket.send(execution_result.encode('utf-8'))  
            self.log_event('execution_result_sent', execution_result)  
  
            client_socket.close()  
            self.log_event('connection_closed', f"Connection closed with server.")  
        except ConnectionResetError:  
            self.log_event('connection_lost', "Connection lost.")  
            client_socket.close()  
  
    def execute_command(self, command):  
        # Simulate command execution  
        execution_logs = {  
            'scan': 'Scan completed.',  
            'encrypt': 'Files encrypted.',  
            'exfiltrate': 'Data exfiltrated.',  
            'persist': 'Persistence established.'  
        }  
        result = execution_logs.get(command, 'Unknown command executed.')  
        time.sleep(random.randint(1, 3))  # Simulate time taken to execute command  
        return result  
  
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
    client = C2Client()  
    client_thread = threading.Thread(target=client.start_client)  
    client_thread.daemon = True  
    client_thread.start()  
  
    try:  
        while True:  
            time.sleep(1)  
    except KeyboardInterrupt:  
        print("\n[!] Shutting down the client.")  