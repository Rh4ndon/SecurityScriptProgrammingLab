from flask import Flask, request, jsonify
import re
app = Flask(__name__)

# Validate endpoint
@app.route('/validate', methods=['POST'])
def validate_input():
    data = request.get_json()
    input_type = data.get('input_type')
    value = data.get('value')
    
    if input_type == "email":
        # Simple email regex
        email_regex = r'^[a-zA-Z0-9._.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9-.]+$'
        is_valid = re.match(email_regex, value) is not None
        return jsonify({'valid': is_valid})
    
    return jsonify({"error": "Unsupported input type"}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=True)
    
    