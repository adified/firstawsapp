from flask import Flask, render_template, redirect, url_for, request, session, flash
import psycopg2
from psycopg2 import sql
import bcrypt
import os

# Set secret key to a random value
app = Flask(__name__)
app.secret_key = os.urandom(24)  # This generates a random 24-byte string

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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        password = request.form['password']

        # Connect to the database
        conn = connect_db()
        cursor = conn.cursor()

        # Retrieve the stored hash for the username
        cursor.execute(
            sql.SQL("SELECT password FROM users WHERE username = %s"),
            [username]
        )

        stored_password_hash = cursor.fetchone()

        # Check if the password is correct
        if stored_password_hash and bcrypt.checkpw(password.encode('utf-8'), stored_password_hash[0].encode('utf-8')):
            # Store user in session
            session['user'] = username
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard'))  # Redirect to dashboard on success
        else:
            cursor.close()
            conn.close()
            return "Invalid credentials!"

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        password = request.form['password']

        # Connect to the database
        conn = connect_db()
        cursor = conn.cursor()

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Check if the username already exists
        cursor.execute(
            sql.SQL("SELECT username FROM users WHERE username = %s"),
            [username]
        )
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Please choose another one.", "error")
        else:
            # Insert the data into the database (with hashed password)
            cursor.execute(
                sql.SQL("INSERT INTO users (username, password) VALUES (%s, %s)"),
                [username, hashed_password.decode('utf-8')]  # Store as string
            )
            conn.commit()
            flash("User added successfully!", "success")

        # Close the connection
        cursor.close()
        conn.close()

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    username = session['user']
    return render_template('dashboard.html', username=username)


@app.route('/logout')
def logout():
    # Remove the user from the session to log them out
    session.pop('user', None)
    return redirect(url_for('login'))  # Redirect to login page after logout


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
