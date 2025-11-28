import os
from functools import wraps
from flask import Flask, request, jsonify, g
import jwt
import time
import threading
from .models import LoginRequest, WithdrawRequest
from pydantic import ValidationError

app = Flask(__name__)
# In production, this should be set as an environment variable
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "your-secret-key")

# --- In-memory database ---
users = {
    1: {
        "user_id": 1,
        "username": "admin",
        "password": "password",
        "is_admin": True,
        "balance": 1000,
    },
    2: {
        "user_id": 2,
        "username": "user",
        "password": "password",
        "is_admin": False,
        "balance": 500,
    },
}
invoices = {
    1: {"invoice_id": 1, "user_id": 1, "amount": 100, "description": "Invoice for user 1"},
    2: {"invoice_id": 2, "user_id": 2, "amount": 200, "description": "Invoice for user 2"},
}
next_user_id = 3
balance_lock = threading.Lock()


# --- Middleware ---
@app.before_request
def before_request():
    g.user = None
    g.auth_error = None  # Store potential error
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user = users.get(decoded["user_id"])
            if not user:
                g.auth_error = ({"error": "User from token not found"}, 401)
            g.user = user
        except jwt.ExpiredSignatureError:
            g.auth_error = ({"error": "Token has expired"}, 401)
        except jwt.InvalidTokenError:
            g.auth_error = ({"error": "Invalid token"}, 401)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.auth_error:
            return jsonify(g.auth_error[0]), g.auth_error[1]
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
        if not g.user.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.auth_error:
            return jsonify(g.auth_error[0]), g.auth_error[1]
        if not g.user:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


# --- Vulnerable Endpoints ---


@app.route("/api/login", methods=["POST"])
def login():
    """Vulnerable to authentication bypass via JWT alg=none"""
    try:
        data = LoginRequest(**request.get_json())
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400

    for user_id, user in users.items():
        if user["username"] == data.username and user["password"] == data.password:
            token = jwt.encode(
                {"user_id": user_id}, app.config["SECRET_KEY"], algorithm="HS256"
            )
            return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/invoices/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice(invoice_id):
    """Vulnerable to IDOR - no authorization check"""
    invoice = invoices.get(invoice_id)
    if invoice:
        return jsonify(invoice)
    return jsonify({"error": "Invoice not found"}), 404


@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
def get_user(user_id):
    """Vulnerable to IDOR/BOLA - no authorization check"""
    # Authorization check: only admin or the user themselves can access the data
    if g.user["user_id"] != user_id and not g.user["is_admin"]:
        return jsonify({"error": "Unauthorized to access this resource"}), 403

    user = users.get(user_id)
    if user:
        # Prevent excessive data exposure
        safe_user = user.copy()
        del safe_user["password"]
        return jsonify(safe_user)
    return jsonify({"error": "User not found"}), 404


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_all_users():
    """Admin-only endpoint"""
    safe_users = {}
    for user_id, user_data in users.items():
        safe_user = user_data.copy()
        del safe_user["password"]
        safe_users[user_id] = safe_user
    return jsonify(safe_users)


def _safe_search_users(query):
    """
    Simulates a safe, parameterized search against the in-memory user data.
    """
    results = []
    # Case-insensitive search in username
    for _, user_data in users.items():
        if query.lower() in user_data["username"].lower():
            safe_user = user_data.copy()
            del safe_user["password"]  # Don't expose sensitive data
            results.append(safe_user)
    return results


@app.route("/api/search", methods=["GET"])
def search():
    """Previously vulnerable to injection, now performs a safe search."""
    query = request.args.get("q", "")
    if not query or len(query) < 2:
        return jsonify({"error": "A search query of at least 2 characters is required"}), 400

    # Simulate a safe, parameterized query
    results = _safe_search_users(query)

    return jsonify({"results": results})


@app.route("/api/payments/withdraw", methods=["POST"])
@login_required
def withdraw():
    """Vulnerable to a race condition (double-spending)"""
    try:
        data = WithdrawRequest(**request.get_json())
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400
    amount = data.amount
    user_id = g.user["user_id"]

    # This lock prevents a race condition where two requests could withdraw
    # funds simultaneously, leading to a negative balance.
    with balance_lock:
        current_balance = users[user_id]["balance"]
        # In a real app, this check-then-set logic should be an atomic
        # database transaction (e.g., SELECT FOR UPDATE).
        if current_balance >= amount:
            users[user_id]["balance"] -= amount
            return jsonify(
                {
                    "message": "Withdrawal successful",
                    "new_balance": users[user_id]["balance"],
                }
            )
        else:
            return jsonify({"error": "Insufficient funds"}), 400


# --- Health Check and Metrics ---


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "ok"})


@app.route("/metrics", methods=["GET"])
def metrics():
    """Metrics endpoint"""
    return jsonify(
        {
            "users_total": len(users),
            "requests_total": len(threading.enumerate()),
            "uptime_seconds": time.time() - app.start_time,
        }
    )


if __name__ == "__main__":
    app.start_time = time.time()
    app.run(debug=True, port=5000)
