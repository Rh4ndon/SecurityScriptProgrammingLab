import re
from html import escape
from bleach import clean

def validate_and_sanitize_form_data(form_data):
    errors = {}
    sanitized_data = {}

    # Validate 'name' field (required)
    if 'name' not in form_data or not form_data['name'].strip():
        errors['name'] = "Name is required."
    else:
        sanitized_data['name'] = form_data['name'].strip()

    # Validate 'email' field (required)
    email_pattern = r'^[a-zA-Z0-9._.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9-.]+$'
    if 'email' not in form_data or not form_data['email'].strip():
        errors['email'] = "Email is required."
    elif not re.match(email_pattern, form_data['email'].strip()):
        errors['email'] = "Invalid email format."
    else:
        sanitized_data['email'] = form_data['email'].strip()

    # Validate 'age' field (optional, must be between 18 and 120)
    if 'age' in form_data and form_data['age']:
        try:
            age = int(form_data['age'])
            if age < 18 or age > 120:
                errors['age'] = "Age must be between 18 and 120."
            else:
                sanitized_data['age'] = age
        except ValueError:
            errors['age'] = "Age must be an integer."

    # Sanitize 'message' field (optional)
    if 'message' in form_data and form_data['message']:
        sanitized_message = sanitize_message(form_data['message'])
        sanitized_data['message'] = sanitized_message

    return {
        "errors": errors,
        "sanitized_data": sanitized_data
    }

def sanitize_message(message):
    # Remove potential JavaScript patterns (e.g., <script> tags and event handlers like 'onclick')
    sanitized_message = clean(message, tags=[], strip=True)  # Remove all HTML tags
    # Remove JavaScript functions like alert(), eval(), etc., including any parameters inside parentheses
    sanitized_message = re.sub(r'\b(alert|eval|document|window|onclick|onerror|onload|script)\s*\(.*?\)', '', sanitized_message, flags=re.IGNORECASE)
    # Optionally, also remove any remaining special characters or HTML entities (if necessary)
    sanitized_message = re.sub(r'([^\w\s])', '', sanitized_message)
    return sanitized_message

# Usage in a web application
form_input = {
    "name": "John Doe",
    "email": "john.doe@example.com",
    "age": "25",
    "message": "<script>alert('Random Command')</script> Hello, this is a test message!"
}

result = validate_and_sanitize_form_data(form_input)
print(result)