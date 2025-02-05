import os
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from authlib.integrations.flask_client import OAuth
from config import Config
import requests
import base64
import json
from email.mime.text import MIMEText
import smtplib


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
TO_EMAIL = os.getenv("TO_EMAIL")
TO_EMAIL_PASSWORD = os.getenv("TO_EMAIL_PASSWORD")
to_email_password = TO_EMAIL_PASSWORD
to_email = TO_EMAIL 


app = Flask(__name__)
app.config.from_object(Config)

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={'scope': 'openid email profile https://www.googleapis.com/auth/gmail.send'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)


# google = oauth.register(
#     name='google',
#     client_id=app.config['GOOGLE_CLIENT_ID'],
#     client_secret=app.config['GOOGLE_CLIENT_SECRET'],
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
#     access_token_url='https://oauth2.googleapis.com/token',
#     api_base_url='https://www.googleapis.com/oauth2/v1/',
#     userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
#     jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
#     client_kwargs={'scope': 'openid email profile https://www.googleapis.com/auth/gmail.send'},
#     server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
# )

user_email = None  
access_token = None 

# to_email_password = app.config['TO_EMAIL_PASSWORD']
# to_email = app.config['TO_EMAIL']


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return google.authorize_redirect(url_for('authorize', _external=True))

@app.route('/celebrate')
def celebrate():
    return render_template('celebrate.html')

@app.route('/authorize')
def authorize():
    global user_email, access_token, user_name  

    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    user_email = user_info['email']
    user_name = user_info['name']
    access_token = token['access_token']

    return render_template('letter.html', email=user_email, user_name = user_name)

@app.route('/send_email', methods=['POST'])
def send_email_route():

    if not user_email or not access_token:
        return jsonify({"message": "Error: User not authenticated"}), 400

    success = send_email(access_token, user_email)

    if success:
        return jsonify({"message": "Email sent successfully!"})
    else:
        return jsonify({"message": "Failed to send email"}), 500

def send_email(access_token, sender_email):
    # to_email = app.config['TO_EMAIL']
    to_email = TO_EMAIL

    subject = f"you have a notification from {sender_email}"
    body = f"Hello,\n\n{user_name} has accepted to become your valentine"   


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
        subject_toUser = f"you have notification"
        body_toUser = f"Hello, You have accepeted Mr {to_email} valentine request..And he is very very happy"

        message_toUser = MIMEText(body_toUser)
        message_toUser["to"] = user_email
        message_toUser["subject"] = subject_toUser

        sendMessageToUSER(message_toUser)
        return True
    else:
        print("Failed to send email:", response.json())
        return False


def sendMessageToUSER(Message):
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
       
        server.login(to_email, to_email_password)
        
        server.sendmail(to_email, user_email, Message.as_string())
        server.quit()
        return jsonify({"success": "Email sent successfully!"})
    

    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)
