from flask import Flask, render_template, redirect, url_for, request, session
import psycopg2
from psycopg2 import sql
import bcrypt  # Import bcrypt for password hashing
import os

# Set secret key to a random value

app = Flask(__name__)
app.secret_key = os.urandom(24)  # This generates a random 24-byte string

# Database connection parameters
db_host = 'database-1.cboukk40mx5j.ap-south-1.rds.amazonaws.com'
db_name = 'firstdb'
db_user = 'postgres'
db_password = 'IftwlDl4KdXHAQcvYmRD'


conn = psycopg2.connect(db_host)
cursor = conn.cursor()


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
        username = request.form['username']
        password = request.form['password']
        
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result and bcrypt.check_password_hash(result[0], password):
            # Store the user info in session
            session['user'] = username
            return redirect(url_for('dashboard'))  # Redirect to the personalized page
        else:
            return 'Invalid credentials', 401

    return render_template('login.html')

# Define a route to display the form and handle form submissions
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Connect to the database
        conn = connect_db()
        cursor = conn.cursor()

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

            # Commit the transaction and close the connection
            conn.commit()
            flash("User added successfully!", "success")

        # Close the connection
        cursor.close()
        conn.close()

    return render_template('index.html')

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

        if stored_password_hash and bcrypt.checkpw(password.encode('utf-8'), stored_password_hash[0].encode('utf-8')):
            return "Login successful!"
        else:
            return "Invalid credentials!"

        cursor.close()
        conn.close()
    
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated
    
    username = session['user']
    return f"Hello {username}, welcome to your personalized page!"


@app.route('/logout')
def logout():
    session.pop('user', None)  # Remove user from session
    return redirect(url_for('login'))  # Redirect to the login page



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)