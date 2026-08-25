"""A deliberately vulnerable Flask app for LOCAL testing only.
Real SQLite DB. Contains intentional SQLi (/login) and IDOR (/profile).
Run on localhost; attack it with the agent. Educational sandbox only."""
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
    c.execute("INSERT INTO users VALUES ('admin', 's3cr3t_pw', 'admin')")
    c.execute("INSERT INTO users VALUES ('alice', 'password123', 'user')")
    conn.commit()
    return conn

db = init_db()

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "x")
    # VULNERABLE: string-formatted SQL (intentional)
    query = f"SELECT role FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cur = db.execute(query)
        row = cur.fetchone()
    except Exception:
        return "Login | Username | Password | Forgot password?", 200
    if row:
        return f"Home | Recent activity | Account settings | Sign out (role={row[0]})", 200
    return "Login | Username | Password | Forgot password?", 200

@app.route("/profile", methods=["GET"])
def profile():
    # VULNERABLE: no authorization check — any id returns that user's data.
    user_id = request.args.get("id", "")
    profiles = {
        "1": "Profile: alice | email: alice@example.com | plan: free",
        "2": "Profile: bob | email: bob@example.com | plan: pro",
        "3": "Profile: admin | email: admin@example.com | plan: enterprise | ssn: 999-00-1234",
    }
    if user_id in profiles:
        return profiles[user_id], 200
    return "Profile not found", 404

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
