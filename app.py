from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import re
import random
import time
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "secure_login_project_secret_key"
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def valid_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email)


def strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not name or not email or not password or not confirm_password:
            flash("All fields are required.", "error")
            return redirect(url_for("register"))

        if len(name) < 3:
            flash("Name must have at least 3 characters.", "error")
            return redirect(url_for("register"))

        if not valid_email(email):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        if not strong_password(password):
            flash("Password must contain uppercase, lowercase, number, special character and minimum 8 characters.", "error")
            return redirect(url_for("register"))

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        hashed_password = hashed_password.decode("utf-8")

        try:
            conn = get_db()

            # Parameterized query protects from SQL injection
            conn.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already exists. Please login.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("login"))

        conn = get_db()

        # Parameterized query protects from SQL injection
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            otp = str(random.randint(100000, 999999))

            session.clear()
            session["pending_user_id"] = user["id"]
            session["pending_name"] = user["name"]
            session["pending_email"] = user["email"]
            session["otp"] = otp
            session["otp_expiry"] = time.time() + 300

            flash(f"Demo OTP: {otp}", "success")
            return redirect(url_for("verify_otp"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "pending_user_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        entered_otp = request.form["otp"].strip()

        if time.time() > session["otp_expiry"]:
            session.clear()
            flash("OTP expired. Please login again.", "error")
            return redirect(url_for("login"))

        if entered_otp == session["otp"]:
            session.permanent = True
            session["user_id"] = session["pending_user_id"]
            session["name"] = session["pending_name"]
            session["email"] = session["pending_email"]

            session.pop("pending_user_id", None)
            session.pop("pending_name", None)
            session.pop("pending_email", None)
            session.pop("otp", None)
            session.pop("otp_expiry", None)

            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP.", "error")
            return redirect(url_for("verify_otp"))

    return render_template("verify_otp.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    create_table()
    app.run(debug=True)