import hashlib
import os
from tkinter import Tk, Label, Entry, Button, StringVar, messagebox

# Global variables for storing the salt and hashed password
stored_salt = None
stored_hash = None

# Function to hash the password
def hash_password(password):
    global stored_salt, stored_hash
    if not password: # Check if the password is empty
        messagebox.showerror("Error", "Password field cannot be empty!")
        return
    stored_salt = os.urandom(16) # Generate a random salt of 16 bytes
    hashed_password = hashlib.sha256(stored_salt + password.encode('utf-8')).hexdigest()
    stored_hash = hashed_password
    messagebox.showinfo("Success", "Password hashed and saved successfully!")

# Function to verify the password
def verify_password(password):
    global stored_salt, stored_hash
    if not stored_salt or not stored_hash: # Check if a password has been hashed
        messagebox.showerror("Error", "No hashed password found! Hash a password first.")
        return
    if not password: # Check if the password is empty
        messagebox.showerror("Error", "Please enter a password.")
        return
    entered_hash = hashlib.sha256(stored_salt + password.encode('utf-8')).hexdigest()
    if entered_hash == stored_hash:
        messagebox.showinfo("Success", "Password is correct!")
    else:
        messagebox.showerror("Error", "Incorrect password. Please try again.")
        
# Tkinter GUI Setup
def create_gui():
    root = Tk()
    root.title("Password Hashing and Verification")
    root.geometry("400x350")
    
    # Title
    title_label = Label(root, text="Password Hashing System", font=("Arial", 16))
    title_label.pack(pady=10)
    
    # Input Label and Entry for Password Hashing
    hash_label = Label(root, text="Enter Password to Hash:")
    hash_label.pack(pady=5)
    hash_var = StringVar()
    hash_entry = Entry(root, textvariable=hash_var, show="*", width=30)
    hash_entry.pack(pady=5)
    
    # Hash Button
    hash_button = Button(root, text="Hash and Save Password", command=lambda: hash_password(hash_var.get()))
    hash_button.pack(pady=10)
    
    
    # Input Label and Entry for Password Verification
    verify_label = Label(root, text="Enter Password to Verify:")
    verify_label.pack(pady=5)
    verify_var = StringVar()
    verify_entry = Entry(root, textvariable=verify_var, show="*", width=30)
    verify_entry.pack(pady=5)
    
    # Verify Button
    verify_button = Button(root, text="Verify Password", command=lambda: verify_password(verify_var.get()))
    verify_button.pack(pady=10)
    
    # Quit Button
    quit_button = Button(root, text="Quit", command=root.quit)
    quit_button.pack(pady=20)
    
    root.mainloop()
    
# Run the GUI
if __name__ == "__main__":
    create_gui()