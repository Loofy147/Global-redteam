from flask import Flask, request, jsonify, g
import jwt
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# --- In-memory database ---
users = {
    1: {'user_id': 1, 'username': 'admin', 'password': 'password', 'is_admin': True, 'balance': 1000},
    2: {'user_id': 2, 'username': 'user', 'password': 'password', 'is_admin': False, 'balance': 500}
}
next_user_id = 3
balance_lock = threading.Lock()

# --- Middleware ---
@app.before_request
def before_request():
    g.user = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user = users.get(decoded['user_id'])
        except jwt.ExpiredSignatureError:
            pass  # Invalid token
        except jwt.InvalidTokenError:
            pass  # Invalid token

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not g.user or not g.user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Vulnerable Endpoints ---

@app.route('/api/login', methods=['POST'])
def login():
    """Vulnerable to authentication bypass via JWT alg=none"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    for user_id, user in users.items():
        if user['username'] == username and user['password'] == password:
            token = jwt.encode({'user_id': user_id}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Vulnerable to IDOR/BOLA - no authorization check"""
    user = users.get(user_id)
    if user:
        # Vulnerable to excessive data exposure (returns password)
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_all_users():
    """Admin-only endpoint"""
    return jsonify(users)

@app.route('/api/search', methods=['GET'])
def search():
    """Vulnerable to injection"""
    query = request.args.get('q', '')
    # In a real app, this might be a database query
    return jsonify({'message': f"Search results for: {query}"})

@app.route('/api/payments/withdraw', methods=['POST'])
def withdraw():
    """Vulnerable to a race condition (double-spending)"""
    data = request.get_json()
    amount = data.get('amount')
    user_id = g.user['user_id'] if g.user else 1 # default to admin for testing

    with balance_lock:
        current_balance = users[user_id]['balance']
        time.sleep(0.01) # Simulate processing time to widen the race window
        if current_balance >= amount:
            users[user_id]['balance'] -= amount
            return jsonify({'message': 'Withdrawal successful', 'new_balance': users[user_id]['balance']})
        else:
            return jsonify({'error': 'Insufficient funds'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
