from flask import Flask, render_template, request, jsonify
import random
import string
import re
import platform

# Platform check for Windows-specific imports
if platform.system() == "Windows":
    import win32api
    import win32con
else:
    print("Running on Linux, pywin32 is not used.")

app = Flask(__name__)

def generate_password(length=12, include_numbers=True, include_symbols=True, include_upper=True, include_lower=True):
    """Generates a secure password with guaranteed distribution of selected types."""
    
    if length < 8:
        return "Password must be at least 8 characters long."

    # List to hold mandatory characters
    password_list = []

    # Ensure at least one character of each selected type
    char_types = []
    
    if include_upper:
        char_types.append(string.ascii_uppercase)
        password_list.append(random.choice(string.ascii_uppercase))
        
    if include_lower:
        char_types.append(string.ascii_lowercase)
        password_list.append(random.choice(string.ascii_lowercase))
        
    if include_numbers:
        char_types.append(string.digits)
        password_list.append(random.choice(string.digits))
        
    if include_symbols:
        char_types.append(string.punctuation)
        password_list.append(random.choice(string.punctuation))

    # Combine all selected character types
    all_characters = ''.join(char_types)

    # Fill the rest of the password length with random characters
    remaining_length = length - len(password_list)

    if remaining_length > 0:
        password_list.extend(random.choices(all_characters, k=remaining_length))

    # Shuffle to avoid predictable patterns
    random.shuffle(password_list)

    # Return the password as a string
    return ''.join(password_list)

def analyze_strength(password):
    """Analyze password strength and return a rating."""
    
    length = len(password)

    # Regex patterns to check complexity
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    # Strength scoring
    score = 0
    if length >= 8:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_symbol:
        score += 1

    # Return strength rating
    if score <= 2:
        return "🔴 Too Weak"
    elif score == 3:
        return "🟡 Weak"
    elif score == 4:
        return "🟢 Strong"
    else:
        return "🔥 Very Strong"

def get_recommendation(password):
    """Returns a recommendation message if the password uses only numbers or symbols."""
    if re.fullmatch(r'\d+', password):
        return "⚠️ Consider adding letters and symbols for stronger security."
    
    if re.fullmatch(r'[!@#$%^&*(),.?":{}|<>]+', password):
        return "⚠️ Adding letters and numbers will make your password more secure."

    return ""

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    """Generates a password and returns it along with strength and recommendations."""
    
    data = request.get_json()
    length = int(data.get('length', 12))
    
    # Enforce min and max length validation
    if length < 8:
        return jsonify({'error': 'Password must be at least 8 characters long.'}), 400
    
    if length > 32:
        return jsonify({'error': 'Maximum allowed length is 32 characters.'}), 400

    include_numbers = data.get('include_numbers', True)
    include_symbols = data.get('include_symbols', True)
    include_upper = data.get('include_upper', True)
    include_lower = data.get('include_lower', True)

    # Generate the password
    password = generate_password(length, include_numbers, include_symbols, include_upper, include_lower)

    if password is None:
        return jsonify({
            'error': 'Please select at least one character type.'
        }), 400

    # Analyze strength only if a password is generated
    strength = analyze_strength(password) if password else ""

    # Get recommendation message
    recommendation = get_recommendation(password) if password else ""

    return jsonify({
        'password': password, 
        'strength': strength,
        'recommendation': recommendation
    })

if __name__ == '__main__':
    app.run(debug=True)
