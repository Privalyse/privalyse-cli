import os
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

def process_user_data(user_data):
    # Unsanitized leak
    email = user_data['email']
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Analyze this user: {email}"}]
    )
    
    # Sanitized (safe)
    phone = user_data['phone']
    masked_phone = mask_pii(phone)
    response2 = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Analyze this phone: {masked_phone}"}]
    )

def mask_pii(text):
    return "***"
