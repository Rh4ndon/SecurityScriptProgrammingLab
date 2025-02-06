import tkinter as tk
from tkinter import scrolledtext, messagebox
from bs4 import BeautifulSoup

# Function to extract content from HTML string
def extract_content():
    html_content = html_entry.get("1.0", tk.END) # get the HTML content from the text widget
    if not html_content.strip():
        messagebox.showerror("Error", "Please enter HTML content.")
        return
    try:
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, "html.parser")
        # Extract title
        title = soup.title.string if soup.title else "No title found"
        # Extract paragraph
        paragraph = [p.get_text() for p in soup.find_all("p")]
        paragraph_text = "\n".join(paragraph) if paragraph else "No paragraph found."
        
        # Extract link
        links = [link['href'] for link in soup.find_all('a', href=True)]
        link_text = "\n".join(links) if links else "No link found."
        
        # Display the results
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Title: {title}\n\n")
        result_text.insert(tk.END, f"Paragraph: {paragraph_text}\n\n")
        result_text.insert(tk.END, f"Link: {link_text}\n\n")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        
# Create the main Tkinter window
app = tk.Tk()
app.title("HTML Content Extractor")
app.geometry("800x600")
 

# Label for HTML content entry
html_label = tk.Label(app, text="Enter HTML content:", font=("Arial", 12))
html_label.pack(pady=5)

# Text widget for user to input HTML content
html_entry = scrolledtext.ScrolledText(app, font=("Arial", 12), wrap=tk.WORD, width=80, height=10)
html_entry.pack(pady=5)

# Button to trigger content extraction
extraction_button = tk.Button(app, text="Extract Content", font=("Arial", 12), command=extract_content)      
extraction_button.pack(pady=10)

# Scroll text widget to display the result
result_text = scrolledtext.ScrolledText(app, font=("Arial", 12), wrap=tk.WORD, width=80, height=25)
result_text.pack(pady=10)

# Run the application
app.mainloop()