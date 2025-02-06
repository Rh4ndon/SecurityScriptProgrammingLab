import tkinter as tk
from tkinter import messagebox


def assess_password_strength(password):
    special_characters = "!@#$%^&*()-_+="
    
    if len(password) < 8:
        return "Weak"
    elif len(password) < 12:
        if all(char.islower() for char in password) or all(char.isupper() for char in password):
            return "Weak"
        elif any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password):
            return "Moderate"
    elif len(password) >= 12:
        if (any(char.islower() for char in password) and 
            any(char.isupper() for char in password) and 
            any(char.isdigit() for char in password) and 
            any(char in special_characters for char in password)):
            return "Strong"
    
    return "Moderate"  # Default to "Moderate" if none of the above match


def check_password_strength():
    password = entry.get()
    strength = assess_password_strength(password)
    messagebox.showinfo("Password Strength", f"Password strength: {strength}")

app = tk.Tk()
app.title("Password Strength Assessment")
app.geometry("300x100")

label = tk.Label(app, text="Enter your password:")
label.pack()

entry = tk.Entry(app, show="*")
entry.pack()

button = tk.Button(app, text="Check Strength", command=check_password_strength)
button.pack()

app.mainloop()