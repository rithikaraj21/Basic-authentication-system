import os
from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

def get_db():
    return sqlite3.connect(DB_PATH)

with get_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB
        )
    """)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        user = get_db().execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if user and bcrypt.checkpw(password, user[0]):
            session["user"] = username
            return redirect("/dashboard")

        return "Invalid credentials"
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hashed = bcrypt.hashpw(
            request.form["password"].encode(),
            bcrypt.gensalt()
        )
        try:
            get_db().execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (request.form["username"], hashed)
            )
            get_db().commit()
            return redirect("/")
        except:
            return "User already exists"
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return f"Welcome {session['user']}"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
