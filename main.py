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

if os.path.exists("master.key"):
    try_master_password = input("What is your main password? ").encode()
else:
    master_password = input("Please set a master password: ").encode()
    master_pass(master_password)

salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)

key = base64.urlsafe_b64encode(kdf.derive(load_key()))
fer = Fernet(key)

while True:
    mode = input("Would you like to (a)dd a new password, (v)iew existing ones or (q)uit? ").lower()
    if mode == "q":
        break
    if mode == "v":
        can_you_access = input("What is the master password? ")
        if can_you_access == master_password:
            view()
        else:
            print("Sorry, that's incorrect. Try again...")
            continue
    elif mode == "a":
        add()
    else:
        print("Invalid Mode")
        continue