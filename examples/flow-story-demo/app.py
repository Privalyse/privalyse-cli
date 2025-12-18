from flask import Flask, request
import logging

app = Flask(__name__)

def process_user_data(data):
    # Transformation
    return f"User data: {data}"

@app.route('/signup', methods=['POST'])
def signup():
    # Source: User Input
    email = request.form.get('email')
    
    # Transformation
    log_message = process_user_data(email)
    
    # Sink: Logging (Leak)
    logging.info(log_message)
    
    return "Signed up!"
