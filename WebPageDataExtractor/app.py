import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup

def extract_data():
    url = input_text.get("1.0", tk.END).strip()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return
    try:
        # Send the GET request to the website
        response = requests.get(url)
        response.raise_for_status()  # Check if the request was successful
        # Parse the webpage content using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        # Extract headings
        output_text.insert(tk.END, "Headings:\n")
        headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        for heading in headings:
            output_text.insert(tk.END, f"{heading.name}: {heading.get_text()}\n")
        # Extract hyperlinks
        output_text.insert(tk.END, "Links:\n")
        links = soup.find_all('a', href=True)
        for link in links:
            output_text.insert(tk.END, f"{link['href']}\n")
        
    except requests.exceptions.RequestException as e:
        output_text.insert(tk.END, f"An error occurred while fetching the webpage: {str(e)}")
    
# Create the main Tkinter window
root = tk.Tk()
root.title("MMDC Web Page Data Extractor")

# Create a label
label = tk.Label(root, text="MMDC Web Page Data Extractor", font=("Arial", 14))
label.pack(pady=10)

# Create an input label and entry
input_label = tk.Label(root, text="Enter the URL of the webpage:")
input_label.pack(pady=5)
input_text = scrolledtext.ScrolledText(root, font=("Arial", 12), wrap=tk.WORD, width=80, height=2)
input_text.pack(pady=5)

# Create a button to trigger the extraction
extract_button = tk.Button(root, text="Extract Data", font=("Arial", 12), command=extract_data)
extract_button.pack(pady=5)

# Create a scrolled text widget to display the extracted data
output_text = scrolledtext.ScrolledText(root, font=("Arial", 12), wrap=tk.WORD, width=80, height=20)
output_text.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()