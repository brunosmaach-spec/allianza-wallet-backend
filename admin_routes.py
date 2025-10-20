# admin_routes.py
import os
from flask import Blueprint, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta

admin_bp = Blueprint('admin', __name__)

# 🔐 Configurações de Segurança
ADMIN_USERS = {
    os.getenv('ADMIN_USER_1'): os.getenv('ADMIN_PASSWORD_1'),
    os.getenv('ADMIN_USER_2'): os.getenv('ADMIN_PASSWORD_2')
}

ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET', 'super-secret-key-change-in-production')

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
@admin_bp.route('/admin/login', methods=['POST'])
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
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, ADMIN_JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            "success": True,
            "token": token,
            "user": username
        }), 200
    
    return jsonify({"error": "Credenciais inválidas"}), 401

# 📊 Dashboard de Pagamentos
@admin_bp.route('/admin/payments', methods=['GET'])
@admin_required
def get_payments():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Buscar todos os pagamentos
        cursor.execute('''
            SELECT id, email, amount, method, status, created_at, tx_hash, processed_at 
            FROM payments 
            ORDER BY created_at DESC
        ''')
        payments = cursor.fetchall()
        
        # Estatísticas
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
                SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as total_value
            FROM payments
        ''')
        stats = cursor.fetchone()
        
        return jsonify({
            "success": True,
            "data": [dict(payment) for payment in payments],
            "stats": dict(stats) if stats else {}
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ✅ Processar Pagamentos PIX Manualmente
@admin_bp.route('/admin/process-payments', methods=['POST'])
@admin_required
def process_payments():
    data = request.json
    payment_ids = data.get('payment_ids', [])
    
    if not payment_ids:
        return jsonify({"error": "Nenhum pagamento selecionado"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("BEGIN")
        
        for payment_id in payment_ids:
            # Buscar pagamento
            cursor.execute(
                "SELECT id, email, amount FROM payments WHERE id = %s AND status = 'pending'",
                (payment_id,)
            )
            payment = cursor.fetchone()
            
            if payment:
                # Buscar usuário pelo email
                cursor.execute(
                    "SELECT id, wallet_address FROM users WHERE email = %s",
                    (payment['email'],)
                )
                user = cursor.fetchone()
                
                if user:
                    # Creditar tokens na carteira do usuário
                    cursor.execute(
                        "UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = 'ALZ'",
                        (payment['amount'], user['id'])
                    )
                    
                    # Registrar no ledger
                    cursor.execute(
                        "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                        (user['id'], 'ALZ', payment['amount'], 'purchase', f'Compra via PIX processada - Payment ID: {payment_id}')
                    )
                    
                    # Atualizar status do pagamento
                    cursor.execute(
                        "UPDATE payments SET status = 'completed', processed_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (payment_id,)
                    )
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"{len(payment_ids)} pagamentos processados com sucesso"
        }), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 📈 Supply e Estatísticas
@admin_bp.route('/admin/supply-stats', methods=['GET'])
@admin_required
def get_supply_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Supply Total
        TOTAL_SUPPLY = 1000000000  # 1 bilhão
        
        # Tokens em circulação
        cursor.execute("SELECT SUM(available + staking_balance) as circulating FROM balances WHERE asset = 'ALZ'")
        circulating_result = cursor.fetchone()
        circulating = circulating_result['circulating'] or 0
        
        # Tokens pendentes
        cursor.execute("SELECT SUM(amount) as pending FROM payments WHERE status = 'pending'")
        pending_result = cursor.fetchone()
        pending = pending_result['pending'] or 0
        
        # Estatísticas de usuários
        cursor.execute("SELECT COUNT(*) as total_users FROM users")
        total_users = cursor.fetchone()['total_users']
        
        return jsonify({
            "success": True,
            "supply": {
                "total": TOTAL_SUPPLY,
                "circulating": circulating,
                "pending_distribution": pending,
                "reserve": TOTAL_SUPPLY - circulating - pending
            },
            "users": {
                "total": total_users
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()