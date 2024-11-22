from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Initialize Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Initialize Limiter for rate limiting
limiter = Limiter(get_remote_address, app=app)

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["user_database"]
users_collection = db["users"]

# Route: Home
@app.route("/")
def home():
    return render_template("home.html")

# Route: Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Validate inputs
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            flash("Username must contain only letters, numbers, and underscores.")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("signup"))

        # Check if username exists
        if users_collection.find_one({"username": username}):
            flash("Username already exists.")
            return redirect(url_for("signup"))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Insert the new user
        users_collection.insert_one({"username": username, "password": hashed_password})
        flash("Signup successful! Please login.")
        return redirect(url_for("login"))

    return render_template("signup.html")

# Route: Login
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Rate limiting to prevent brute-force attacks
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Fetch user from the database
        user = users_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["username"] = username
            flash("Login successful!")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.")
            return redirect(url_for("login"))

    return render_template("login.html")

# Route: Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("You have been logged out.")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
