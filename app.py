from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re

# SHA-1 Helper Function: Left Rotate
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

# SHA-1 Hashing Function
def sha1(message):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    message = bytearray(message, 'ascii')
    og_len = len(message) * 8
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)
    message += og_len.to_bytes(8, byteorder='big')

    for i in range(0, len(message), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(message[i + j*4: i + j*4 + 4], byteorder='big')
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return f'{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}'

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"

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

        # Hash the password using SHA-1
        hashed_password = sha1(password)

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
        if user:
            # Hash the entered password to compare with the stored hash
            hashed_password = sha1(password)
            if user["password"] == hashed_password:
                session["username"] = username
                flash("Login successful!")
                return redirect(url_for("home"))

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
