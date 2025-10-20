from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import time
import jwt
from functools import wraps

# Importar funções do banco
try:
    from database_neon import get_db_connection, init_db
    print("✅ Usando banco de dados Neon (PostgreSQL)")
except ImportError as e:
    print(f"❌ Erro ao importar database_neon: {e}")
    exit(1)

from generate_wallet import generate_polygon_wallet
from backend_staking_routes import staking_bp

print("Iniciando o servidor Flask...")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

# 🔐 Configurações de Segurança Admin
ADMIN_USERS = {
    os.getenv('ADMIN_USER_1', 'admin'): os.getenv('ADMIN_PASSWORD_1', 'admin123'),
    os.getenv('ADMIN_USER_2', 'admin2'): os.getenv('ADMIN_PASSWORD_2', 'admin456')
}

ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET', 'super-secret-key-change-in-production')
SITE_ADMIN_TOKEN = os.getenv('SITE_ADMIN_TOKEN', 'site-admin-token-secret')

# Inicializa o banco de dados
init_db()

# Registrar blueprint de staking
app.register_blueprint(staking_bp, url_prefix="/staking")

# 🔒 Middleware de Autenticação Admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({"error": "Token de administrador necessário"}), 401
        
        try:
            payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=['HS256'])
            if payload.get('role') != 'admin':
                return jsonify({"error": "Acesso não autorizado"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# 🔑 Login Admin
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Credenciais necessárias"}), 400
    
    if username in ADMIN_USERS and ADMIN_USERS[username] == password:
        # Gerar token JWT
        token = jwt.encode({
            'username': username,
            'role': 'admin',
            'exp': datetime.utcnow() + time.timedelta(hours=24)
        }, ADMIN_JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            "success": True,
            "token": token,
            "user": username
        }), 200
    
    return jsonify({"error": "Credenciais inválidas"}), 401

# 🔄 Rota para o Site processar pagamentos
@app.route('/api/site/purchase', methods=['POST'])
def site_process_purchase():
    """Processar compra do site e creditar tokens"""
    data = request.json
    email = data.get('email')
    amount = data.get('amount')
    method = data.get('method')
    
    if not email or not amount:
        return jsonify({"error": "Email e valor são obrigatórios"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("BEGIN")
        
        # 1. Registrar pagamento
        cursor.execute(
            "INSERT INTO payments (email, amount, method, status) VALUES (%s, %s, %s, 'pending') RETURNING id",
            (email, amount, method)
        )
        payment_id = cursor.fetchone()['id']
        
        # 2. Buscar ou criar usuário
        cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        user_created = False
        wallet_address = None
        
        if not user:
            # Criar usuário sem senha (será ativado no primeiro login na wallet)
            private_key, wallet_address = generate_polygon_wallet()
            cursor.execute(
                "INSERT INTO users (email, wallet_address, private_key) VALUES (%s, %s, %s) RETURNING id",
                (email, wallet_address, private_key)
            )
            user_id = cursor.fetchone()['id']
            user_created = True
        else:
            user_id = user['id']
            wallet_address = user['wallet_address']
        
        # 3. Verificar/criar saldo
        cursor.execute("SELECT user_id FROM balances WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO balances (user_id, available) VALUES (%s, %s)",
                (user_id, 0.0)
            )
        
        # 4. Creditar tokens IMEDIATAMENTE
        cursor.execute(
            "UPDATE balances SET available = available + %s WHERE user_id = %s",
            (amount, user_id)
        )
        
        # 5. Registrar no ledger
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
            (user_id, 'ALZ', amount, 'purchase', f'Compra via {method} - Site')
        )
        
        # 6. Atualizar pagamento como completed
        cursor.execute(
            "UPDATE payments SET status = 'completed', user_id = %s, processed_at = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id, payment_id)
        )
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Compra processada com sucesso!",
            "payment_id": payment_id,
            "user_created": user_created,
            "wallet_address": wallet_address,
            "user_id": user_id
        }), 200
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro no processamento da compra: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 🔄 Rota para Admin do Site
@app.route('/api/site/admin/payments', methods=['GET'])
def site_admin_payments():
    """Listar pagamentos para o admin do site"""
    admin_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not admin_token or admin_token != SITE_ADMIN_TOKEN:
        return jsonify({"error": "Não autorizado"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT p.id, p.email, p.amount, p.method, p.status, p.created_at, 
                   p.processed_at, u.wallet_address, u.nickname
            FROM payments p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        ''')
        payments = cursor.fetchall()
        
        return jsonify({
            "success": True,
            "data": [dict(payment) for payment in payments]
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 🔄 Rota para estatísticas do admin do site
@app.route('/api/site/admin/stats', methods=['GET'])
def site_admin_stats():
    """Estatísticas para o admin do site"""
    admin_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not admin_token or admin_token != SITE_ADMIN_TOKEN:
        return jsonify({"error": "Não autorizado"}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Estatísticas de pagamentos
        cursor.execute('''
            SELECT 
                COUNT(*) as total_payments,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_payments,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_payments,
                SUM(amount) as total_amount,
                SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as completed_amount
            FROM payments
        ''')
        payment_stats = cursor.fetchone()
        
        # Estatísticas de usuários
        cursor.execute("SELECT COUNT(*) as total_users FROM users")
        user_stats = cursor.fetchone()
        
        # Supply statistics
        TOTAL_SUPPLY = 1000000000  # 1 bilhão
        cursor.execute("SELECT SUM(available + staking_balance) as circulating FROM balances WHERE asset = 'ALZ'")
        circulating_result = cursor.fetchone()
        circulating = circulating_result['circulating'] or 0
        
        cursor.execute("SELECT SUM(amount) as pending FROM payments WHERE status = 'pending'")
        pending_result = cursor.fetchone()
        pending = pending_result['pending'] or 0
        
        return jsonify({
            "success": True,
            "stats": {
                "payments": dict(payment_stats),
                "users": dict(user_stats),
                "supply": {
                    "total": TOTAL_SUPPLY,
                    "circulating": float(circulating),
                    "pending_distribution": float(pending),
                    "reserve": TOTAL_SUPPLY - float(circulating) - float(pending)
                }
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 🔄 Processar Pagamentos PIX Manualmente (Admin)
@app.route('/api/site/admin/process-payments', methods=['POST'])
def site_admin_process_payments():
    """Processar pagamentos PIX manualmente"""
    admin_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not admin_token or admin_token != SITE_ADMIN_TOKEN:
        return jsonify({"error": "Não autorizado"}), 401
    
    data = request.json
    payment_ids = data.get('payment_ids', [])
    
    if not payment_ids:
        return jsonify({"error": "Nenhum pagamento selecionado"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("BEGIN")
        
        processed_count = 0
        
        for payment_id in payment_ids:
            # Buscar pagamento pendente
            cursor.execute(
                "SELECT id, email, amount FROM payments WHERE id = %s AND status = 'pending'",
                (payment_id,)
            )
            payment = cursor.fetchone()
            
            if payment:
                # Buscar usuário pelo email
                cursor.execute(
                    "SELECT id FROM users WHERE email = %s",
                    (payment['email'],)
                )
                user = cursor.fetchone()
                
                if user:
                    # Creditar tokens
                    cursor.execute(
                        "UPDATE balances SET available = available + %s WHERE user_id = %s",
                        (payment['amount'], user['id'])
                    )
                    
                    # Registrar no ledger
                    cursor.execute(
                        "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                        (user['id'], 'ALZ', payment['amount'], 'purchase', f'Compra PIX processada - Payment ID: {payment_id}')
                    )
                    
                    # Atualizar status do pagamento
                    cursor.execute(
                        "UPDATE payments SET status = 'completed', user_id = %s, processed_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (user['id'], payment_id)
                    )
                    
                    processed_count += 1
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"{processed_count} pagamentos processados com sucesso",
            "processed_count": processed_count
        }), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ===== ROTAS EXISTENTES DA WALLET (MANTIDAS) =====

def get_user_id_from_token(token):
    try:
        parts = token.split("_")
        if len(parts) >= 3 and parts[0] == "mock" and parts[1] == "token":
            return int(parts[2])
    except (ValueError, IndexError):
        pass
    return None

@app.before_request
def authenticate_request():
    if request.method == "OPTIONS":
        from flask import make_response
        return make_response("", 200)

    if request.path in ["/register", "/login", "/first-time-setup", "/check-user"]:
        return

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token is missing or invalid"}), 401

    token = auth_header.split(" ")[1]
    user_id = get_user_id_from_token(token)

    if not user_id:
        return jsonify({"error": "Invalid authentication token"}), 401
    
    request.user_id = user_id

@app.route("/register", methods=["POST"])
def register_user():
    data = request.json
    email = data.get("email")
    nickname = data.get("nickname")
    password = data.get("password")
    
    if not email or not password or not nickname:
        return jsonify({"error": "Email, nickname, and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "User with this email already exists"}), 409

        private_key, wallet_address = generate_polygon_wallet()
        hashed_password = generate_password_hash(password)
        
        cursor.execute(
            "INSERT INTO users (email, password, nickname, wallet_address, private_key) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (email, hashed_password, nickname, wallet_address, private_key)
        )
        
        result = cursor.fetchone()
        user_id = result["id"]

        cursor.execute(
            "INSERT INTO balances (user_id, asset, available, staking_balance) VALUES (%s, %s, %s, %s)",
            (user_id, "ALZ", 0.0, 0.0)
        )
        conn.commit()

        auth_token = f"mock_token_{user_id}_{int(time.time())}"

        return jsonify({
            "user": {"id": user_id, "email": email, "nickname": nickname, "wallet_address": wallet_address},
            "token": auth_token,
            "message": "User registered successfully"
        }), 201

    except Exception as e:
        conn.rollback()
        print(f"❌ Erro no registro: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id, email, nickname, wallet_address, private_key, password FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()

        if not user_data or not check_password_hash(user_data["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        user = dict(user_data)
        del user["password"]

        auth_token = f"mock_token_{user['id']}_{int(time.time())}"

        cursor.execute("SELECT available, locked, staking_balance FROM balances WHERE user_id = %s AND asset = 'ALZ'", (user["id"],))
        balance_data = cursor.fetchone()
        
        balance = {"available_balance": 0.0, "locked_balance": 0.0, "staking_balance": 0.0, "total_balance": 0.0}
        if balance_data:
            balance["available_balance"] = float(balance_data["available"]) if balance_data["available"] else 0.0
            balance["staking_balance"] = float(balance_data["staking_balance"]) if balance_data["staking_balance"] else 0.0
            balance["total_balance"] = balance["available_balance"] + balance["staking_balance"]

        return jsonify({
            "user": user, 
            "token": auth_token, 
            "message": "Login successful", 
            "balance": balance
        }), 200
        
    except Exception as e:
        print(f"❌ Erro no login: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
    finally:
        conn.close()

@app.route("/first-time-setup", methods=["POST"])
def first_time_setup():
    """Configurar senha para usuário que comprou tokens mas não tem conta completa"""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nickname = data.get('nickname')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Email não encontrado"}), 404

        cursor.execute("SELECT password FROM users WHERE email = %s AND password IS NOT NULL", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Conta já está ativa. Use o login normal."}), 400

        hashed_password = generate_password_hash(password)
        cursor.execute(
            "UPDATE users SET password = %s, nickname = %s, updated_at = CURRENT_TIMESTAMP WHERE email = %s",
            (hashed_password, nickname, email)
        )

        cursor.execute("SELECT available, staking_balance FROM balances WHERE user_id = %s", (user['id'],))
        balance_data = cursor.fetchone()

        conn.commit()

        auth_token = f"mock_token_{user['id']}_{int(time.time())}"

        return jsonify({
            "success": True,
            "user": {
                "id": user['id'],
                "email": email,
                "nickname": nickname,
                "wallet_address": user['wallet_address']
            },
            "token": auth_token,
            "balance": {
                "available_balance": float(balance_data['available']) if balance_data else 0.0,
                "staking_balance": float(balance_data['staking_balance']) if balance_data else 0.0,
                "total_balance": (float(balance_data['available']) if balance_data else 0.0) + 
                               (float(balance_data['staking_balance']) if balance_data else 0.0)
            }
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/check-user", methods=["POST"])
def check_user():
    """Verificar situação do usuário para primeiro acesso"""
    data = request.json
    email = data.get('email')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({
                "exists": False,
                "has_password": False,
                "has_purchase": False
            }), 200
        
        cursor.execute("SELECT id FROM payments WHERE email = %s AND status = 'completed'", (email,))
        has_purchase = cursor.fetchone() is not None
        
        return jsonify({
            "exists": True,
            "has_password": user['password'] is not None,
            "has_purchase": has_purchase
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ... (manter todas as outras rotas existentes da wallet: /auth/me, /balances/me, /purchase, etc.)

if __name__ == "__main__":
    print("Tentando iniciar o servidor Flask...")
    try:
        app.run(debug=True, port=5000)
    except Exception as e:
        print(f"Erro ao iniciar o servidor Flask: {e}")