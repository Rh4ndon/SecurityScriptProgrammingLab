import tkinter as tk
from tkinter import messagebox
import random

def generate_and_save():
    # Generate a random number between 1 and 100
    random_number = random.randint(1, 100)
    
    # Display the  random number in a message box
    messagebox.showinfo("Random Number", f"The generated random number is: {random_number}")
    
    # Save the random number to a file
    with open("./random_number.txt", "w") as file:
        file.write(f"Generated Random Number: {random_number}\n")
    
    # Confirm that the file has been saved
    messagebox.showinfo("File Saved", "The random number has been saved to 'random_number.txt'.")
    
root = tk.Tk()
root.title("Random Number Generator") # Set the title of the window

label = tk.Label(root, text="Click the button to generate a random number.", font=("Arial", 14))
label.pack(pady=10) # Add some padding


generate_button = tk.Button(root, text="Generate and Save", command=generate_and_save)
generate_button.pack(pady=20)

root.mainloop()