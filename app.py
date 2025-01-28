from flask import Flask, render_template, redirect, url_for, request, session, flash
import psycopg2
import bcrypt
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
import boto3
import json

# Set secret key to a random value
app = Flask(__name__)
app.secret_key = os.urandom(24)  # This generates a random 24-byte string

from flask_session import Session
from redis import Redis

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'your_app_name:'
app.config['SESSION_REDIS'] = Redis(host='127.0.0.1', port=6379)
Session(app)

def get_rds_secret(secret_name, region_name="ap-south-1"):
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

secret = get_rds_secret("rds_firstapp")
if secret:
    db_password = secret['password']  # Replace 'password' with the key used in your secret
    db_username = secret['username']  # Similarly for username

# Function to connect to the database
def connect_db():
    return psycopg2.connect(
        host="database-1.cboukk40mx5j.ap-south-1.rds.amazonaws.com",
        database="firstdb",
        user=db_username,
        password=db_password
    )

# Function to generate OTP and store it in the database
def generate_otp(email, username):
    otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
    conn = connect_db()
    cursor = conn.cursor()

    # Insert the OTP into the database
    cursor.execute(
        "INSERT INTO otp (username, otp, created_at) VALUES (%s, %s, %s)",
        (username, otp, datetime.now(timezone.utc))
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
        (datetime.now(timezone.utc) - timedelta(seconds=30),)
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
        cursor.execute("SELECT username FROM users WHERE username = %s ", (username, ))
        user_exists = cursor.fetchone()

        if user_exists:
            flash("Username or email already exists.", "error")
        else:
            # Generate OTP and send to email
            otp = generate_otp(email, username)
            send_email(email, f"Your OTP is {otp}")
            session['pending_user'] = {'username': username, 'email': email, 'password': hashed_password.decode('utf-8')}
            flash("OTP sent to your email. Please verify.", "info")
            return redirect(url_for('verify_otp'))

        cursor.close()
        conn.close()

    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user' not in session:
        flash("No registration in progress. Please start the registration process.", "error")
        return redirect(url_for('register'))  # Redirect to registration if pending_user is not set

    if request.method == 'POST':
        email = session['pending_user']['email']
        username = session['pending_user']['username']
        entered_otp = request.form['otp']

        conn = connect_db()
        cursor = conn.cursor()

        # Retrieve OTP from the database
        cursor.execute("SELECT otp, created_at FROM otp WHERE username = %s ORDER BY created_at DESC LIMIT 1", (username,))
        result = cursor.fetchone()

        if result:
            stored_otp, created_at = result
            print(type(stored_otp), type(entered_otp))
            print((stored_otp),(entered_otp))
            print((stored_otp) == (entered_otp))
            if stored_otp == entered_otp:
                # Ensure created_at is timezone-aware before comparison
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)  # Make it timezone-aware if it's naive

                if (datetime.now(timezone.utc) - created_at).total_seconds() <= 30:
                    # OTP is valid, proceed with user creation
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
                flash("Invalid OTP.", "error")


        cursor.close()
        conn.close()

    return render_template('verify_otp.html')  # Ensure you're rendering the OTP verification page

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        stored_password_hash = cursor.fetchone()

        if stored_password_hash and bcrypt.checkpw(password.encode('utf-8'), stored_password_hash[0].encode('utf-8')):
            session['user'] = username
            return redirect(url_for('dashboard'))

        flash("Invalid credentials. Please try again.", "error")
        cursor.close()
        conn.close()

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated
    
    username = session['user']
    return f"Hello {username}, welcome to your personalized page!"


if __name__ == '__main__':
    app.run(debug=True)


# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000)