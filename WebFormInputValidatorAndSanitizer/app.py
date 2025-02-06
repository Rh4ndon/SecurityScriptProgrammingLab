from flask import Flask, request, render_template_string
import re
from html import escape
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Form template
form_template = '''
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com?plugins=forms,typography"></script>
    <script type="text/javascript">
        {% if alert_message %}
            alert("{{ alert_message }}");
        {% endif %}
    </script>
  </head>
  <body>
    <div class="relative bg-cover bg-center h-screen" style="background-image: url('https://lh4.googleusercontent.com/PPrCQY3gz9pglgAlEZ53puN3rFVsPFy7kdrsvokvnyZ_TpHuqTAf4ki0SxF-sMKxv3bM8o_-CuaDpU4KJULnJvI=w16383');">
    <div class="absolute inset-0 bg-black opacity-50"></div>
    <div class="relative z-10 flex flex-col items-center justify-center h-full text-white">
    <img src="https://lh4.googleusercontent.com/DYSPlNVEPKx0oFUGLic8xV-Xay9TR6Q7_R0JA6NKqmafo7p-yw_LFkc8D5YnBm64PbbFJzTtT4XDbBCPRoLxpNs=w16383" alt="Logo" class="mb-6 w-20 h-auto" />
        <h1 class="text-4xl font-bold mb-2">Fairetail Form</h1>
        <form method="POST" class="bg-zinc-800 bg-opacity-70 p-6 rounded-lg shadow-lg w-96">
            <div class="mb-4">
                <label for="name" class="block text-sm font-medium">Name</label>
                <input type="text" id="name" name="name" class="mt-1 block w-full p-2 border border-zinc-300 rounded-md text-black" />
            </div>
            <div class="mb-4">
                <label for="email" class="block text-sm font-medium">Email</label>
                <input type="text" id="email" name="email" class="mt-1 block w-full p-2 border border-zinc-300 rounded-md text-black" />
            </div>
            <div class="mb-4">
                <label for="age" class="block text-sm font-medium">Age</label>
                <input type="number" id="age" name="age" class="mt-1 block w-full p-2 border border-zinc-300 rounded-md text-black" />
            </div>
            <div class="mb-4">
                <label for="message" class="block text-sm font-medium">Message</label>
                <textarea id="message" name="message" rows="4" class="mt-1 block w-full p-2 border border-zinc-300 rounded-md text-black"></textarea>
            </div>
            <button type="submit" class="w-full bg-yellow-500 text-white p-2 rounded-md hover:bg-yellow-400">Submit</button>
        </form>
    </div>
</div>
  </body>
</html>
'''
# Route for the form
@app.route("/", methods=["GET", "POST"])
# Function to render the form
def form():
    alert_message = None
    if request.method == "POST":
        form_data = request.form
        errors, sanitized_data = validate_and_sanitize_form_data(form_data)
        
        if errors:
            app.logger.info("Validation Errors: %s", errors)
            alert_message = "Form submission failed.\\n" + "\\n".join([f"{field}: {msg}" for field, msg in errors.items()])
        else:
            app.logger.info("Sanitized Data: %s", sanitized_data)
            sanitized_summary = "\\n".join([f"{key}: {value}" for key, value in sanitized_data.items()])
            alert_message = f"Form submitted successfully!\\n\\nSanitized Data:\\n{sanitized_summary}"
    
    return render_template_string(form_template, alert_message=alert_message)

# Function to validate and sanitize form data
def validate_and_sanitize_form_data(form_data):
    errors = {}
    sanitized_data = {}

    if not form_data.get('name', '').strip():
        errors['name'] = "Name is required."
    else:
        sanitized_data['name'] = form_data['name'].strip()

    email_pattern = r'^[a-zA-Z0-9._.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9-.]+$'
    if not form_data.get('email', '').strip():
        errors['email'] = "Email is required."
    elif not re.match(email_pattern, form_data['email'].strip()):
        errors['email'] = "Invalid email format."
    else:
        sanitized_data['email'] = form_data['email'].strip()

    if form_data.get('age'):
        try:
            age = int(form_data['age'])
            if age < 18 or age > 120:
                errors['age'] = "Age must be between 18 and 120."
            else:
                sanitized_data['age'] = age
        except ValueError:
            errors['age'] = "Age must be an integer."

    if form_data.get('message'):
        sanitized_data['message'] = escape(form_data['message'])

    return errors, sanitized_data

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
