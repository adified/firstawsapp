from flask import Flask, render_template, redirect, url_for, request, session, flash
import psycopg2
from psycopg2 import sql
import bcrypt
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

# Set secret key to a random value
app = Flask(__name__)
app.secret_key = os.urandom(24)  # This generates a random 24-byte string

from datetime import datetime, timedelta
import random

def generate_otp(email):
    otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
    conn = connect_db()
    cursor = conn.cursor()

    # Insert the OTP into the database
    cursor.execute(
        "INSERT INTO otp (email, otp, created_at) VALUES (%s, %s, %s)",
        (email, otp, datetime.utcnow())
    )

    conn.commit()
    cursor.close()
    conn.close()
    return otp

def clean_up_expired_otps():
    conn = connect_db()
    cursor = conn.cursor()

    # Delete OTPs older than 30 seconds
    cursor.execute(
        "DELETE FROM otp WHERE created_at < %s",
        (datetime.utcnow() - timedelta(seconds=30),)
    )

    conn.commit()
    cursor.close()
    conn.close()


import boto3
import json

def get_secret():
    secret_name = "smtp_app_pass"
    region_name = "us-east-1"  # Replace with your AWS region

    # Create a Secrets Manager client
    client = boto3.client('secretsmanager', region_name=region_name)

    try:
        # Retrieve the secret value
        response = client.get_secret_value(SecretId=secret_name)
        secret = response['SecretString']
        return json.loads(secret)
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None

# Retrieve email credentials
credentials = get_secret()
app.config['MAIL_USERNAME'] = 'adarshagarwal.iitb@gmail.com'
# app.config['MAIL_USERNAME'] = credentials['email']
app.config['MAIL_PASSWORD'] = credentials['smtp_pass']

# Database connection parameters
db_host = 'database-1.cboukk40mx5j.ap-south-1.rds.amazonaws.com'
db_name = 'firstdb'
db_user = 'postgres'
db_password = 'IftwlDl4KdXHAQcvYmRD'


# Create a function to establish a database connection
def connect_db():
    connection = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_password
    )
    return connection

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = connect_db()
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute("SELECT username, email FROM users WHERE username = %s OR email = %s", (username, email))
        user_exists = cursor.fetchone()

        if user_exists:
            flash("Username or email already exists.", "error")
        else:
            # Generate and send OTP
            otp = random.randint(100000, 999999)
            otp_storage[email] = otp
            send_otp(email, otp)
            session['pending_user'] = {'username': username, 'email': email, 'password': hashed_password.decode('utf-8')}
            return redirect(url_for('verify_otp'))

        conn.close()
    return render_template('register.html')


def send_email(to_email, message_body):
    sender_email = "your_email@gmail.com"
    sender_password = "your_app_password"  # Use app password if using Gmail with 2FA

    # Create the email content
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP Verification Code"
    msg.attach(MIMEText(message_body, 'plain'))

    try:
        # Connect to the Gmail SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)  # Login
            server.send_message(msg)  # Send the email
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form['email']
    otp = generate_otp(email)

    # Use send_email to send the OTP
    send_email(email, f"Your OTP is {otp}")
    return "OTP sent successfully!"


def verify_otp(email, entered_otp):
    conn = connect_db()
    cursor = conn.cursor()

    # Retrieve the OTP and creation time from the database
    cursor.execute(
        "SELECT otp, created_at FROM otp WHERE email = %s ORDER BY created_at DESC LIMIT 1",
        (email,)
    )
    result = cursor.fetchone()

    if result:
        stored_otp, created_at = result
        # Check if the OTP matches and is within the 30-second expiry
        if stored_otp == entered_otp and (datetime.utcnow() - created_at).total_seconds() <= 30:
            return True

    return False

@app.route('/verify_otp', methods=['POST'])
def verify_otp_route():
    email = request.form['email']
    entered_otp = request.form['otp']

    if verify_otp(email, entered_otp):
        return "OTP verified successfully!"
    else:
        return "Invalid or expired OTP."

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        stored_password_hash = cursor.fetchone()

        if stored_password_hash and bcrypt.checkpw(password.encode('utf-8'), stored_password_hash[0].encode('utf-8')):
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "error")
        conn.close()
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    return f"Welcome, {username}! This is your personalized dashboard."

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)