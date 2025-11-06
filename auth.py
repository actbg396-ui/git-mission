import bcrypt
import os

USER_DATA_FILE = "users.txt"

def hash_password(plain_text_password):
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt)
    hashed_password = password_hash.decode("utf-8")
    return hashed_password

def verify_password():
    plain_text_password= ()
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt)
    return password_hash == plain_text_password

def register_user(username, password):
    hashed_password = hash_password(password)
    with open('users.txt','a') as file:
        file.write(username + '\n')
        file.write(hashed_password + '\n')
    return True

def user_exists(username):
    with open('users.txt','r') as file:
        users = file.readlines(username)
    return False

def login_user(username, password):
    username = "Tine G"
    with open('users.txt','r') as file:
        if user_exists(username):
            hashed_password = hash_password(password)
        else:
            print("User not found")
            return

def validate_user(username):
    username = "Tine G"







