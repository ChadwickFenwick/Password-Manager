import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Write the key file for the encryption, run once and commit out.
"""
def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
"""

# Load key file for decryption purposes.
def load_key():
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

# View the passwords in a list from the file
def view():
    with open('password.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            print("User: ", user, "| Password: ", fer.decrypt(passw.encode()).decode())

# Add the passwords to the file
def add():
    name = input("Account Name: ")
    pwd = input("Password: ")

    with open('password.txt', 'a') as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")

# Ask for the main password and confirm it works with the file.
def master_pass(x):
    x = Fernet.generate_key()
    with open("master.key", "wb") as master_file:
        master_file.write(x)

def master_return():
    file = open("master.key", "rb")
    master_file_open = file.read()
    master_key_return = fer_master.decrypt(master_file_open.encode()).encode()
    file.close()
    return master_key_return

salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)

key = base64.urlsafe_b64encode(kdf.derive(load_key()))
fer = Fernet(key)
master_key_set = base64.urlsafe_b64encode(kdf.derive(master_return()))
fer_master = Fernet(master_key_set)

if os.path.exists("master.key"):
    try_master_password = input("What is your master password? ").encode()
    key_check = master_return()
    if try_master_password == key_check:
        password_is_valid = True
    else:
        password_is_valid = False
else:
    master_password = input("Please set a master password: ").encode()
    master_pass(master_password)

while True:
    mode = input("Would you like to (a)dd a new password, (v)iew existing ones or (q)uit? ").lower()
    if mode == "q":
        break
    if mode == "v":
        can_you_access = input("What is the master password? ")
        if can_you_access == password_is_valid:
            view()
        else:
            print("Sorry, that's incorrect. Try again...")
            continue
    elif mode == "a":
        add()
    else:
        print("Invalid Mode")
        continue