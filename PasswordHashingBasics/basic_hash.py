import hashlib

password = input("Please enter your password: ")
hashed_password = hashlib.sha256(password.encode()).hexdigest()
print(f"Your hashed password is: {hashed_password}")