import hashlib
import os

password = input("Please enter your password: ")
salt = os.urandom(16)  # Generate a random salt of 16 bytes
salted_password = salt + password.encode()

hashed_password_with_salt = hashlib.sha256(salted_password).hexdigest()
print(f"Your hashed password is: {hashed_password_with_salt}")
print(f"Your salt is: {salt.hex()}")