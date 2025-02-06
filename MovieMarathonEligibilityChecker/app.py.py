import tkinter as tk
from tkinter import messagebox
from datetime import datetime

def check_eligibility():
    try:
        # Get user input
        dob_input = entry.get()
        # Parse the date of birth
        dob = datetime.strptime(dob_input, "%Y-%m-%d")
        today = datetime.today()
        
        # Calculate the age
        age = today.year - dob.year
        # Adjust for birthdays that haven't occurred this year yet
        if (today.month, today.day) < (dob.month, dob.day):
            age -= 1
        
        # Check eligibility
        if age >= 18:
            messagebox.showinfo("Eligibility", "You are eligible to watch movies!")
        else:
            messagebox.showinfo("Eligibility", "You are not eligible to watch movies.")
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid birth date in the format YYYY-MM-DD.")

# Create the GUI
app = tk.Tk()
app.title("Movie Marathon Eligibility Checker")
app.geometry("400x200")

label = tk.Label(app, text="Enter your birth date (YYYY-MM-DD):", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(app, font=("Arial", 12), width=25)
entry.pack(pady=5)

button = tk.Button(app, text="Check Eligibility", font=("Arial", 12), command=check_eligibility)
button.pack(pady=10)

app.mainloop()