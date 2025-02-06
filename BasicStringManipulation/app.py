import tkinter as tk
from tkinter import messagebox

def reverse_string():
    user_input = entry.get() # Get the user input
    reveresed_string = user_input[::-1] # Reverse the string
    messagebox.showinfo("Reverse String", f"The reverse string is: {reveresed_string}") 
    # Show the result in a message box
    
root = tk.Tk()
root.title("String Reverser") # Set the title of the window

label = tk.Label(root, text="Enter a string to reverse:")
label.pack(pady=10) # Add some padding

entry = tk.Entry(root, font=("Arial", 14), width=30)
entry.pack(pady=10) # Add some padding

reverse_button = tk.Button(root, text="Reverse String", command=reverse_string, font=("Arial", 14))
reverse_button.pack(pady=20)

root.mainloop()

    