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


import boto3
import json

def get_secret():
    secret_name = "flask_email_credentials"
    region_name = "your-region"  # Replace with your AWS region

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
app.config['MAIL_USERNAME'] = credentials['email']
app.config['MAIL_PASSWORD'] = credentials['password']

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

def send_otp(email, otp):
    msg = EmailMessage()
    msg.set_content(f"Your OTP for registration is: {otp}")
    msg['Subject'] = "Your Registration OTP"
    msg['From'] = SENDER_EMAIL
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.send_message(msg)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = session['pending_user']['email']
        entered_otp = request.form['otp']

        if otp_storage.get(email) == int(entered_otp):
            # OTP is correct, register the user
            user_data = session.pop('pending_user')
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (user_data['username'], user_data['email'], user_data['password']))
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.", "error")
    return render_template('verify_otp.html')

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