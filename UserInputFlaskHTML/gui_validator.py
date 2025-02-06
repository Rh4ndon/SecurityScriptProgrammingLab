import tkinter as tk
from tkinter import messagebox
import requests

# Function to send input to Flask for validation
def validate_input():
    input_value = entry.get()
    input_type = input_type_var.get()
    
    if not input_value:
        messagebox.showerror("Error", "Input cannot be empty!")
        return
    
    # Send input to Flask API
    try:
        response = requests.post("http://localhost:5000/validate", json={"input_type": input_type, "value": input_value})
        result = response.json()
        if response.status_code == 200:
            if result["valid"]:
                messagebox.showinfo("Validation Result", F"The {input_type} is valid!")
            else:
                messagebox.showerror("Validation Result", F"The {input_type} is invalid!")
        else:
            messagebox.showerror("Error", result.get("error", "Unknown error"))
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Could not connect to the server: {str(e)}")
        
# Tkinter setup
root = tk.Tk()
root.title("Web Input Validator")

# Input type dropdown
input_type_var = tk.StringVar(value="email")
tk.Label(root, text="Select Input Type:").pack(pady=5)
tk.OptionMenu(root, input_type_var, "email").pack(pady=5)

# Input field
tk.Label(root, text="Enter Input:").pack(pady=5)
entry = tk.Entry(root, width=30)
entry.pack(pady=5)

# Validate Button
validate_button = tk.Button(root, text="Validate Input", command=validate_input)
validate_button.pack(pady=10)

root.mainloop()