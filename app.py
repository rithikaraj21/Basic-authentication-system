import os
from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)

# SAFE fallback (prevents crash)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")
get("SECRET_KEY")


def get_db():
    return sqlite3.connect("users.db")

# Create users table
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

        db = get_db()
        user = db.execute(
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
        username = request.form["username"]
        password = bcrypt.hashpw(
            request.form["password"].encode(),
            bcrypt.gensalt()
        )

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            db.commit()
            return redirect("/")
        except:
            return "User already exists"

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", user=session["user"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run()
