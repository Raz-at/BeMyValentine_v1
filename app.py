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
from flask_sqlalchemy import SQLAlchemy
from models import User
import uuid
from sqlalchemy import select

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
MY_ENCRYPTION_KEY = os.getenv("MY_ENCRYPTION_KEY")
DB_URL = os.getenv("DATABASE_URL")


app = Flask(__name__)
app.config.from_object(Config)

# app.config['SQLALCHEMY_DATABASE_URI'] = app.config['DB_URL']
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

with app.app_context():
    db.create_all()


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
    session['user_name_message']  = None   
    return render_template('index.html')


@app.route('/<sender_email>')
def index(sender_email):    
    # key = app.config['MY_ENCRYPTION_KEY']
    key = MY_ENCRYPTION_KEY  

    decryptrd_email_user_id = decrypt_user_email(sender_email,key)

    # session['user_name_message'] = decryptrd_email

    session['UNIQUE_USER_ID'] = decryptrd_email_user_id

    exists = db.session.query(User).filter(User.sender_id == decryptrd_email_user_id).count() > 0
    if exists:
        return render_template('error.html', message="This link has already been used."), 403  
    
   
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

        user_email = user_info.get('email')
        user_name = user_info.get('name')
        user_id_guid = str(uuid.uuid4())

        message = None

        sender_id = session.get('UNIQUE_USER_ID')
        if not sender_id:
            sender_id = None
        else:
            user = db.session.get(User,sender_id)
            message = user.message

        add_user = User(name=user_name,email=user_email,user_id=user_id_guid,sender_id = sender_id)
        db.session.add(add_user)
        db.session.commit()

        unique_user_id = add_user.user_id

        session['user_email'] = user_email
        session['user_name'] = user_name
        session['access_token'] = token.get('access_token')


        final_email = session.get('UNIQUE_USER_ID')
        if not final_email:
            return render_template('sent_letter.html', email=session['user_email'], user_name=session['user_name'], user_id = unique_user_id)
        else:
            return render_template('letter.html', email=session['user_email'], user_name=session['user_name'], user_id = unique_user_id, message = message)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/send_email_with_link', methods=['POST'])
def send_email_link_route():
    access_token = session.get('access_token')
    data = request.get_json()
    user_email_link = data.get("email")

    unique_user_id = data.get("user_id")
    message = data.get("message")
    user = db.session.get(User, unique_user_id)
    
    user.message = message
    user.email_to = user_email_link

    if not user:
        return jsonify({"message": "Error: User not found"}), 404
    db.session.commit() 
    
    if not access_token:
        return jsonify({"message": "Error: User not authenticated"}), 400

    success = send_email_link(access_token, user_email_link,unique_user_id)
    return jsonify({"message": "Email sent successfully!"}) if success else jsonify({"message": "Failed to send email"}), 500

def send_email_link(access_token, user_email_link,unique_user_id):

    #this is sender user_email
    user_email = session.get('user_email')

    subject = "Open the link for suprise"

    unique_user_id = unique_user_id
    encrypted_user_id = encrypt_email(unique_user_id)
    BACKEND_URL = "https://bemyvalentine-v1.onrender.com"
    # BACKEND_URL = "http://127.0.0.1:5000"

    # link = f"{BACKEND_URL}/{encrypted_email}" 
    link = f"{BACKEND_URL}/{encrypted_user_id}" 
    print("this is link = ",link)

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

    data = request.get_json()
    
    respondent_user_id = data.get("user_id")

    
    user_data = db.session.get(User,respondent_user_id)
    
    response = data.get('response')
    user_id = session.get('UNIQUE_USER_ID')

    user=db.session.get(User,user_id)
    final_email = user.email
    
    #this is to add the from email in the receiver tab
    user_data.email_from = final_email
    
    
    if not user:
        return jsonify({"message": "Error: User not found"}), 404

    user_data.response = response
    db.session.commit()

    if not final_email or not access_token:
        return jsonify({"message": "Error: User not authenticated"}), 400

    success = send_email(access_token, final_email)
    return jsonify({"message": "Email sent successfully!"}) if success else jsonify({"message": "Failed to send email"}), 500

def send_email(access_token, sender_email):
    to_email = sender_email

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
    else:
        print("Failed to send email:", response.json())
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
    decrypted_email = unpad(cipher.decrypt(encrypted_email), AES.block_size).decode('utf-8')
    return decrypted_email



if __name__ == '__main__':
    app.run(debug=True)
