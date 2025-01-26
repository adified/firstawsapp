from flask import Flask, render_template, redirect, url_for, request, session, flash
import psycopg2
import bcrypt
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import boto3
import json

# Set secret key to a random value
app = Flask(__name__)
app.secret_key = os.urandom(24)  # This generates a random 24-byte string

# Function to connect to the database
def connect_db():
    return psycopg2.connect(
        host="database-1.cboukk40mx5j.ap-south-1.rds.amazonaws.com",
        database="firstdb",
        user="postgres",
        password="IftwlDl4KdXHAQcvYmRD"
    )

# Function to generate OTP and store it in the database
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

# Function to clean up expired OTPs (older than 30 seconds)
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

# Function to retrieve secret credentials from AWS Secrets Manager
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

# Retrieve email credentials from Secrets Manager
credentials = get_secret()
app.config['MAIL_USERNAME'] = 'adarshagarwal.iitb@gmail.com'  # Replace with email from Secrets Manager if needed
app.config['MAIL_PASSWORD'] = credentials['smtp_pass']

# Function to send OTP email
def send_email(to_email, message_body):
    sender_email = app.config['MAIL_USERNAME']
    sender_password = app.config['MAIL_PASSWORD']
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP Verification Code"
    msg.attach(MIMEText(message_body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

# Route for the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for registration
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
            # Generate OTP and send to email
            otp = generate_otp(email)
            send_email(email, f"Your OTP is {otp}")
            session['pending_user'] = {'username': username, 'email': email, 'password': hashed_password.decode('utf-8')}
            flash("OTP sent to your email. Please verify.", "info")
            return redirect(url_for('verify_otp'))

        cursor.close()
        conn.close()

    return render_template('register.html')

# Route for OTP verification
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = session['pending_user']['email']
        entered_otp = request.form['otp']

        conn = connect_db()
        cursor = conn.cursor()

        # Retrieve OTP from the database
        cursor.execute("SELECT otp, created_at FROM otp WHERE email = %s ORDER BY created_at DESC LIMIT 1", (email,))
        result = cursor.fetchone()

        if result:
            stored_otp, created_at = result
            if stored_otp == int(entered_otp) and (datetime.utcnow() - created_at).total_seconds() <= 30:
                # OTP is valid, create user in the database
                pending_user = session.pop('pending_user')
                cursor.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (pending_user['username'], pending_user['email'], pending_user['password'])
                )
                conn.commit()
                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid or expired OTP.", "error")
        else:
            flash("No OTP found. Please try again.", "error")

        cursor.close()
        conn.close()

    return render_template('verify_otp.html')

# Route for login (for testing purposes)
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

# if __name__ == '__main__':
#     app.run(debug=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)