import tkinter as tk
from tkinter import messagebox
from datetime import datetime

def calculate_age():
    # Get the user's birth date
    birth_date_str = entry.get()
    try:
        birth_date = datetime.strptime(birth_date_str, "%Y-%m-%d")
        today = datetime.today()
        
        # Calculate age
        age = today.year - birth_date.year
        # Adjust for birthdays that haven't occurred this year yet
        if (today.month, today.day) < (birth_date.month, birth_date.day):
            age -= 1
        
        # Display the result
        messagebox.showinfo("Age Calculator", f"You are {age} years old.")
    except ValueError:
        # Handle invalid input format
        messagebox.showerror("Invalid Input", "Please enter a valid birth date in the format YYYY-MM-DD.")

app = tk.Tk()
app.title("Age Calculator")
app.geometry("400x200")

label = tk.Label(app, text="Enter your birth date (YYYY-MM-DD):", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(app, font=("Arial", 12), width=25)
entry.pack(pady=5)

button = tk.Button(app, text="Calculate Age", font=("Arial", 12), command=calculate_age)
button.pack(pady=10)

app.mainloop()