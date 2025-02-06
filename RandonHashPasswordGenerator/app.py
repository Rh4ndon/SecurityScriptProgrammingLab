import tkinter as tk
from tkinter import messagebox
import random
import string
from datetime import datetime

def generate_password_and_save():
    # Ensure password has at least one lowercase, one uppercase, one digit, and one special character
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    
    while True:
        password_length = random.randint(8, 16)
        password = ''.join(random.choice(characters) for _ in range(password_length))
        
        # Check if password meets all requirements
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*" for c in password)):
            break
    
    # Display the password in a message box
    messagebox.showinfo("Random Password", f"The generated random password is: {password}")
    
    # Save the password with a timestamp to a file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("passwords.txt", "a") as file:
        file.write(f"[{timestamp}] Generated Password: {password}\n")
    
    # Confirm that the file has been saved
    messagebox.showinfo("File Saved", "The password has been saved to 'passwords.txt'.")

# Create GUI
root = tk.Tk()
root.title("Random Password Generator")

label = tk.Label(root, text="Click the button to generate a random password.", font=("Arial", 14))
label.pack(pady=10) # Add some padding

# Generate Password Button
tk.Button(root, text="Generate Password", command=generate_password_and_save).pack(pady=20)

# Quit Button
quit_button = tk.Button(root, text="Quit", command=root.quit)
quit_button.pack(pady=20)


root.mainloop()
