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

# View the passwords in a list
def view():
    with open('password.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            print("User: ", user, "| Password: ", fer.decrypt(passw.encode()).decode())

# Add the passwords
def add():
    name = input("Account Name: ")
    pwd = input("Password: ")

    with open('password.txt', 'a') as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")

# Ask for the main password and confirm it works with the file.
try:
    main_password = input("What is your main password? ").encode()

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)

    key = base64.urlsafe_b64encode(kdf.derive(main_password))
    fer = Fernet(key)

    while True:
        mode = input("Would you like to (a)dd a new password, (v)iew existing ones or (q)uit? ")
        if mode == "q":
            break
        if mode == "v":
            view()
        elif mode == "a":
            add()
        else:
            print("Invalid Mode")
            continue
except:
    print("That password is invalid, please try again.")