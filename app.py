import os
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from authlib.integrations.flask_client import OAuth
from flask_session import Session  # Import Flask-Session
from config import Config
import requests
import base64
import json
from email.mime.text import MIMEText
import smtplib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad



GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
MY_ENCRYPTION_KEY = os.getenv("MY_ENCRYPTION_KEY")


app = Flask(__name__)
app.config.from_object(Config)

app.secret_key = os.urandom(24)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

oauth = OAuth(app)

google = oauth.register(
    name='google',
    # client_id=app.config['GOOGLE_CLIENT_ID'],
    # client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={'scope': 'openid email profile https://www.googleapis.com/auth/gmail.send'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/<sender_email>')
def index(sender_email):

    # key = app.config['MY_ENCRYPTION_KEY']
    key = MY_ENCRYPTION_KEY

    decryptrd_email = decrypt_user_email(sender_email,key)

    session['user_name_message'] = decryptrd_email
    
    return render_template('index.html')


@app.route('/login')
def login():
    return google.authorize_redirect(url_for('authorize', _external=True))


@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/celebrate')
def celebrate():
    return render_template('celebrate.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204  

@app.route('/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()

        session['user_email'] = user_info.get('email')
        session['user_name'] = user_info.get('name')
        session['access_token'] = token.get('access_token')


        final_email = session.get('user_name_message')

        if not final_email:
            return render_template('sent_letter.html', email=session['user_email'], user_name=session['user_name'])
        else:
            return render_template('letter.html', email=session['user_email'], user_name=session['user_name'])

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/send_email_with_link', methods=['POST'])
def send_email_link_route():
    access_token = session.get('access_token')
    data = request.get_json()
    user_email_link = data.get("email")

    if not access_token:
        return jsonify({"message": "Error: User not authenticated"}), 400

    success = send_email_link(access_token, user_email_link)
    return jsonify({"message": "Email sent successfully!"}) if success else jsonify({"message": "Failed to send email"}), 500

def send_email_link(access_token, user_email_link):

    user_email = session.get('user_email')

    subject = "Open the link for suprise"

    encrypted_email = encrypt_email(user_email)
    
    link = f"http://127.0.0.1:5000/{encrypted_email}"
    body = f"Hello,\nPlease go to this link: \n{link}"

    message = MIMEText(body)
    message["to"] = user_email_link
    message["subject"] = subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")

    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"raw": raw_message})

    response = requests.post(url, headers=headers, data=payload)
    return response.status_code == 200

@app.route('/send_email', methods=['POST'])
def send_email_route():
    access_token = session.get('access_token')
    # user_email = session.get('user_email')    
    final_email = session.get('user_name_message')

    if not final_email or not access_token:
        return jsonify({"message": "Error: User not authenticated"}), 400

    success = send_email(access_token, final_email)
    return jsonify({"message": "Email sent successfully!"}) if success else jsonify({"message": "Failed to send email"}), 500

def send_email(access_token, sender_email):
    to_email = sender_email

    # to_email = app.config['TO_EMAIL']

    user_name = session.get('user_name', 'User')

    subject = f"You have a notification from {to_email}"
    body = f"Hello,\n\n{user_name} has accepted to become your valentine."

    message = MIMEText(body)
    message["to"] = to_email
    message["subject"] = subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")

    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"raw": raw_message})

    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 200:
        return True        
        # return sendMessageToUSER(sender_email,access_token)
    else:
        print("Failed to send email:", response.json())
        return False

def sendMessageToUSER(sender_email,access_token):
    try:

        to_email = sender_email
        from_email =  session.get('user_email')   
        user_name = session.get('user_name')

        subject = f"You have a notification from {to_email}"
        body = f"Hello,\n\n{user_name} has accepted to become your valentine."

        message = MIMEText(body)
        message["to"] = to_email
        message["subject"] = subject

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")

        url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = json.dumps({"raw": raw_message})

        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 200:
            return True        
        else:
            print("Failed to send email:", response.json())
            return False
        
    except Exception as e:
        print("Error sending email to user:", str(e))
        return False

def encrypt_email(email):
    key = MY_ENCRYPTION_KEY
    # key = app.config['MY_ENCRYPTION_KEY']


    if len(key) < 16:
        key = key.ljust(16, '0')  
    elif len(key) > 16:
        key = key[:16] 
    key = key.encode('utf-8')  

    cipher = AES.new(key, AES.MODE_CBC)
    padded_email = pad(email.encode(), AES.block_size)
    encrypted_email = cipher.encrypt(padded_email)
    encoded_cipher = base64.b32encode(cipher.iv + encrypted_email).decode('utf-8')
    return encoded_cipher

def decrypt_user_email(encoded_cipher, key):
    print(10)

    if len(key) < 16:
        key = key.ljust(16, '0')  
    elif len(key) > 16:
        key = key[:16]      
    key = key.encode('utf-8')

    missing_padding = len(encoded_cipher) % 8
    if missing_padding:
        encoded_cipher += "=" * (8 - missing_padding)

    data = base64.b32decode(encoded_cipher)    
    iv = data[:16]
    encrypted_email = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)    
    print(1)
    decrypted_email = unpad(cipher.decrypt(encrypted_email), AES.block_size).decode('utf-8')
    return decrypted_email

if __name__ == '__main__':
    app.run(debug=True)
