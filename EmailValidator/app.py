# Import Tkinter for GUI and re for regular expression validation
import tkinter as tk
from tkinter import messagebox
import re

# Create the main application window
root =tk.Tk()
root.title("Email Validator")
root.geometry("400x200")

# Add a label and entry field for the email input
tk.Label(root, text="Enter your email address:", font=("Arial", 14)).pack(pady=10)
email_entry = tk.Entry(root, font=("Arial", 12), width=30)
email_entry.pack(pady=5)

def validate_email():
    email = email_entry.get()
    # Regular expression to validate the email
    pattern = r"^[^@]+@[^@]+\.[a-zA-Z]{2,}$"
    
    if re.match(pattern, email):
        messagebox.showinfo("Validation Result", "Valid Email Address!")
    else:
        messagebox.showerror("Validation Result", "Invalid Email Address. Ensure it: \n" "- Contain one '@' \n" "- Has chracter before and after '@' \n" "- Ends with a valid domain extension (e.g., example.com)")
    
# Add a button to validate the email
validate_button = tk.Button(root, text="Validate Email", font=("Arial", 12), command=validate_email, bg="blue", fg="white")
validate_button.pack(pady=20)

# Run the application loop
root.mainloop()