import html
from flask import Flask, request, render_template_string
import re
from html import escape
import logging
import hashlib
import os
from email_validator import validate_email, EmailNotValidError

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
    <div class="relative bg-cover bg-center h-screen" style="background-image: url('{{ url_for('static', filename='pexels-timothy-paule-ii-2002717.jpg') }}');">
    <div class="absolute inset-0 bg-black opacity-50"></div>
    <div class="relative z-10 flex flex-col items-center justify-center h-full text-white">
    <img src="{{ url_for('static', filename='fairetail.png') }}" alt="Logo" class="mb-6 w-20 h-auto" />
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
                <label for="password" class="block text-sm font-medium">Password</label>
                <input type="password" id="password" name="password" class="mt-1 block w-full p-2 border border-zinc-300 rounded-md text-black" />
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
    # Validate 'name' field (required)
    name = form_data.get('name', '').strip()
    if not name:
        errors['name'] = "Name is required."
    else:
        # Use a regular expression to validate the name
        if not re.match(r"^[A-Za-z\s'-]+$", name):
            errors['name'] = "Invalid characters in name."
        else:
            sanitized_data['name'] = html.escape(name)

    # Validate 'email' field (required, email format)
    email = form_data.get('email', '').strip()
    if not email:
        errors['email'] = "Email is required."
    else:
        try:
            validated_email = validate_email(email)
            sanitized_data['email'] = validated_email.email  # Normalized email
        except EmailNotValidError as e:
            errors['email'] = str(e)

    # Validate 'password' field (required) and determine its strength
    password = form_data.get('password', '').strip()
    special_characters = "!@#$%^&*()-_+="

    if not password:
        errors['password'] = "Password is required."
    else:
        if len(password) < 8:
            errors['password'] = "Weak: Password must be at least 8 characters long."
        elif len(password) < 12:
            if all(char.islower() for char in password) or all(char.isupper() for char in password):
                errors['password'] = "Weak: Password must contain both uppercase and lowercase letters."
            elif any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password):
                sanitized_data['password'] = escape(password)  # Sanitize the password
                sanitized_data['password_strength'] = "Moderate"
            else:
                errors['password'] = "Weak: Password must include a mix of letters and numbers."
        elif len(password) >= 12:
            if (any(char.islower() for char in password) and 
                any(char.isupper() for char in password) and 
                any(char.isdigit() for char in password) and 
                any(char in special_characters for char in password)):
                sanitized_data['password'] = escape(password)  # Sanitize the password
                sanitized_data['password strength'] = "Strong"

                salt = os.urandom(16)  # Generate a random salt of 16 bytes
                salted_password = salt + sanitized_data['password'].encode()
                hashed_password_with_salt = hashlib.sha256(salted_password).hexdigest()
                
                sanitized_data['password salt'] = salt.hex()
                sanitized_data['hashed password'] = hashed_password_with_salt
                
                # Store the password hash and salt in a text file
                with open('passwords.txt', 'a') as f:
                    f.write(f"{sanitized_data['email']}: {hashed_password_with_salt} {salt.hex()}\n")
                    
               


            else:
                errors['password'] = "Moderate: Password must include special characters, numbers, and letters."


    
    # Validate 'age' field (optional, between 18 and 120)
    if form_data.get('age'):
        try:
            age = int(form_data['age'])
            if age < 18 or age > 120:
                errors['age'] = "Age must be between 18 and 120."
            else:
                sanitized_data['age'] = age
        except ValueError:
            errors['age'] = "Age must be an integer."
            
    # Validate 'message' field (optional)
    if form_data.get('message'):
        sanitized_data['message'] = escape(form_data['message'])

    return errors, sanitized_data

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
