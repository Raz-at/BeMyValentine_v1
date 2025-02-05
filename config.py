import os
from dotenv import load_dotenv

load_dotenv()  

class Config:
    SECRET_KEY = os.urandom(24)
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    TO_EMAIL = os.getenv("TO_EMAIL")
    TO_EMAIL_PASSWORD = os.getenv("SMTP_PASSWORD")
    
