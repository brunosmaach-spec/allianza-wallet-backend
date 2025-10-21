from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import time
import jwt
from functools import wraps
import hmac
import hashlib
import secrets

# ✅ STRIPE IMPORT - VERSÃO CORRIGIDA
STRIPE_AVAILABLE = False
stripe = None

try:
    import stripe
    STRIPE_AVAILABLE = True
    print("✅ Stripe importado com sucesso!")
except ImportError as e:
    print(f"❌ Stripe não pôde ser importado: {e}")
    print("⚠️ Funcionalidades de cartão desativadas")

# Importar funções do banco
try:
    from database_neon import get_db_connection, init_db
    print("✅ Usando banco de dados Neon (PostgreSQL)")
except ImportError as e:
    print(f"❌ Erro ao importar database_neon: {e}")
    exit(1)

from generate_wallet import generate_polygon_wallet
from backend_staking_routes import staking_bp

print("🚀 Iniciando servidor Flask Allianza Wallet...")

app = Flask(__name__)

# ✅ CORS CONFIGURADO PARA TODOS OS DOMÍNIOS
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:5173",        # Vite dev
            "http://localhost:3000",        # Next.js dev
            "https://allianza.tech",        # Site vitrine
            "https://www.allianza.tech",    # Site vitrine (www)
            "https://wallet.allianza.tech", # Wallet
            "https://www.wallet.allianza.tech" # Wallet (www)
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# 🔐 CONFIGURAÇÕES DE SEGURANÇA ADMIN CORRIGIDAS
ADMIN_USERS = {
    os.getenv('ADMIN_USER_1', 'admin'): os.getenv('ADMIN_PASSWORD_1', 'admin123'),
    os.getenv('ADMIN_USER_2', 'admin2'): os.getenv('ADMIN_PASSWORD_2', 'admin456')
}

# ✅ TOKEN CORRETO - IGUAL AO FRONTEND
ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET', 'CdE25$$$')
SITE_ADMIN_TOKEN = os.getenv('SITE_ADMIN_TOKEN', 'allianza_super_admin_2024_CdE25$$$')

# Configurações de Pagamento
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_default_secret_change_in_production')
NOWPAYMENTS_IPN_SECRET = os.getenv('NOWPAYMENTS_IPN_SECRET', 'rB4Ic28l8posIjXA4fx90GuGnHagAxEj')

# Configurar Stripe apenas se disponível
if STRIPE_AVAILABLE:
    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
    if stripe.api_key:
        print("✅ Stripe configurado com sucesso!")
    else:
        print("❌ STRIPE_SECRET_KEY não encontrada")
        STRIPE_AVAILABLE = False
else:
    print("⚠️ Stripe não disponível - funcionalidades de cartão desativadas")

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

# 🔄 FUNÇÃO PARA PROCESSAR PAGAMENTOS AUTOMATICAMENTE
def process_automatic_payment(email, amount, method, external_id):
    """Processar pagamento automaticamente e creditar tokens"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("BEGIN")
        
        print(f"🔄 Processando pagamento automático: {email} - {amount} ALZ - {method}")
        
        # Registrar pagamento
        cursor.execute(
            "INSERT INTO payments (email, amount, method, status, tx_hash) VALUES (%s, %s, %s, 'completed', %s) RETURNING id",
            (email, amount, method, external_id)
        )
        payment_id = cursor.fetchone()['id']
        print(f"✅ Pagamento registrado: ID {payment_id}")
        
        # Buscar ou criar usuário
        cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        user_created = False
        if not user:
            # Criar usuário automaticamente
            private_key, wallet_address = generate_polygon_wallet()
            # ✅ CORREÇÃO: Gerar senha temporária
            temp_password = f"temp_{secrets.token_hex(8)}"
            hashed_password = generate_password_hash(temp_password)
            
            cursor.execute(
                "INSERT INTO users (email, password, wallet_address, private_key, nickname) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (email, hashed_password, wallet_address, private_key, f"User_{email.split('@')[0]}")
            )
            user_id = cursor.fetchone()['id']
            user_created = True
            print(f"👤 Usuário criado: {email} - Carteira: {wallet_address}")
        else:
            user_id = user['id']
            wallet_address = user['wallet_address']
            print(f"👤 Usuário existente: {email} - ID: {user_id}")
        
        # Verificar/criar saldo
        cursor.execute("SELECT user_id FROM balances WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO balances (user_id, available) VALUES (%s, %s)",
                (user_id, 0.0)
            )
            print(f"💰 Saldo criado para usuário {user_id}")
        
        # Creditar tokens
        cursor.execute(
            "UPDATE balances SET available = available + %s WHERE user_id = %s",
            (amount, user_id)
        )
        print(f"💰 Tokens creditados: {amount} ALZ para {email}")
        
        # Registrar no ledger
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
            (user_id, 'ALZ', amount, 'purchase', f'Compra automática via {method} - ID: {external_id}')
        )
        
        # Atualizar pagamento
        cursor.execute(
            "UPDATE payments SET status = 'completed', user_id = %s, processed_at = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id, payment_id)
        )
        
        conn.commit()
        print(f"🎉 Pagamento automático processado com sucesso: {email} - {amount} ALZ")
        
        return {
            "success": True,
            "payment_id": payment_id,
            "user_id": user_id,
            "user_created": user_created,
            "wallet_address": wallet_address
        }
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro processamento automático: {e}")
        raise
    finally:
        conn.close()

# 💳 ROTA PARA CRIAR SESSÃO STRIPE - CORRIGIDA
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """Criar sessão de checkout Stripe"""
    if not STRIPE_AVAILABLE:
        print("❌ Stripe não disponível para criar sessão")
        return jsonify({'error': 'Stripe não disponível'}), 503
        
    try:
        data = request.json
        amount = data.get('amount')
        email = data.get('email')
        
        if not amount or not email:
            return jsonify({'error': 'Amount e email são obrigatórios'}), 400
        
        print(f"💳 Criando sessão Stripe: {email} - {amount} centavos")
        
        # ✅ VERIFICAÇÃO ROBUSTA
        if not stripe or not hasattr(stripe, 'checkout') or not hasattr(stripe.checkout, 'Session'):
            return jsonify({'error': 'Stripe não configurado corretamente'}), 503
        
        # Criar sessão de checkout
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'brl',
                    'product_data': {
                        'name': 'Allianza Tokens (ALZ)',
                        'description': 'Compra de tokens ALZ para a plataforma Allianza'
                    },
                    'unit_amount': amount,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url='https://allianza.tech/success',
            cancel_url='https://allianza.tech/cancel',
            customer_email=email,
            metadata={'email': email, 'amount_brl': amount / 100}
        )
        
        print(f"✅ Sessão Stripe criada: {session.id}")
        return jsonify({'id': session.id})
        
    except Exception as e:
        print(f"❌ Erro criar sessão Stripe: {e}")
        return jsonify({'error': str(e)}), 400

# 🌐 WEBHOOKS PARA PAGAMENTOS AUTOMÁTICOS

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Webhook para pagamentos Stripe (Cartão)"""
    if not STRIPE_AVAILABLE:
        return jsonify({'error': 'Stripe não disponível'}), 503
        
    try:
        payload = request.get_data()
        sig_header = request.headers.get('Stripe-Signature')
        
        print(f"📥 Webhook Stripe recebido: {request.headers}")
        
        # Verificar assinatura do webhook
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            print(f"❌ Payload inválido: {e}")
            return jsonify({'error': 'Invalid payload'}), 400
        except stripe.error.SignatureVerificationError as e:
            print(f"❌ Assinatura inválida: {e}")
            return jsonify({'error': 'Invalid signature'}), 401
        
        print(f"📊 Evento Stripe: {event['type']}")
        
        if event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']
            email = payment_intent.get('receipt_email') or payment_intent['metadata'].get('email')
            amount = payment_intent['amount'] / 100  # Converter de centavos para unidades
            payment_id = payment_intent['id']
            
            if email and amount > 0:
                result = process_automatic_payment(email, amount, 'credit_card', payment_id)
                return jsonify(result), 200
            else:
                print("⚠️ Email ou valor inválido no webhook Stripe")
                return jsonify({'error': 'Invalid email or amount'}), 400
                
        elif event['type'] == 'charge.succeeded':
            charge = event['data']['object']
            email = charge.get('billing_details', {}).get('email')
            amount = charge['amount'] / 100
            payment_id = charge['id']
            
            if email and amount > 0:
                result = process_automatic_payment(email, amount, 'credit_card', payment_id)
                return jsonify(result), 200
        
        return jsonify({'success': True, 'message': 'Event processed'}), 200
        
    except Exception as e:
        print(f"❌ Erro webhook Stripe: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/webhook/nowpayments', methods=['POST'])
def nowpayments_webhook():
    """Webhook para pagamentos NowPayments (Cripto)"""
    try:
        # Verificar assinatura do webhook
        received_signature = request.headers.get('x-nowpayments-ipn-signature')
        payload = request.get_data(as_text=True)
        
        print(f"📥 Webhook NowPayments recebido")
        print(f"📧 Headers: {dict(request.headers)}")
        print(f"📦 Payload: {payload}")
        
        if not received_signature:
            print("❌ Assinatura IPN não fornecida")
            return jsonify({'error': 'Missing signature'}), 401
        
        # Calcular assinatura esperada
        expected_signature = hmac.new(
            bytes(NOWPAYMENTS_IPN_SECRET, 'utf-8'),
            msg=bytes(payload, 'utf-8'),
            digestmod=hashlib.sha512
        ).hexdigest()
        
        # Verificar assinatura
        if not hmac.compare_digest(received_signature, expected_signature):
            print("❌ Assinatura IPN inválida")
            return jsonify({'error': 'Invalid signature'}), 401
        
        data = request.json
        print(f"📊 Dados NowPayments: {data}")
        
        # Processar diferentes status de pagamento
        payment_status = data.get('payment_status')
        if payment_status in ['finished', 'confirmed']:
            email = data.get('customer_email') or data.get('buyer_email')
            amount = float(data.get('pay_amount', 0))
            payment_id = data.get('payment_id')
            
            if email and amount > 0:
                # Processar pagamento automaticamente
                result = process_automatic_payment(email, amount, 'crypto', payment_id)
                print(f"✅ Pagamento NowPayments processado: {email} - {amount} ALZ")
                return jsonify(result), 200
            else:
                print("⚠️ Dados incompletos no webhook NowPayments")
                return jsonify({'error': 'Incomplete data'}), 400
                
        elif payment_status == 'failed':
            payment_id = data.get('payment_id')
            print(f"❌ Pagamento NowPayments falhou: {payment_id}")
            return jsonify({'success': True, 'message': 'Payment failed logged'}), 200
        else:
            print(f"📊 Status intermediário NowPayments: {payment_status}")
            return jsonify({'success': True, 'message': 'Intermediate status received'}), 200
            
    except Exception as e:
        print(f"❌ Erro webhook NowPayments: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/webhook/mercadopago', methods=['POST'])
def mercadopago_webhook():
    """Webhook para pagamentos Mercado Pago (PIX/Cartão)"""
    try:
        data = request.json
        print(f"📥 Webhook Mercado Pago: {data}")
        
        event_type = data.get('type')
        event_action = data.get('action')
        
        if event_type == 'payment' and event_action == 'payment.created':
            payment_data = data.get('data', {})
            payment_id = payment_data.get('id')
            
            # Buscar detalhes do pagamento via API do Mercado Pago
            # (seria necessário fazer uma requisição adicional)
            
        return jsonify({'success': True}), 200
        
    except Exception as e:
        print(f"❌ Erro webhook Mercado Pago: {e}")
        return jsonify({'error': str(e)}), 400

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
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, ADMIN_JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            "success": True,
            "token": token,
            "user": username
        }), 200
    
    return jsonify({"error": "Credenciais inválidas"}), 401

# 🔄 Rota para o Site processar pagamentos - CORRIGIDA (SEM CRÉDITO AUTOMÁTICO)
@app.route('/api/site/purchase', methods=['POST'])
def site_process_purchase():
    """Processar compra do site - TODOS OS PAGAMENTOS FICAM PENDENTES"""
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
        
        # 1. Registrar pagamento PRIMEIRO (SEMPRE PENDENTE)
        cursor.execute(
            "INSERT INTO payments (email, amount, method, status) VALUES (%s, %s, %s, 'pending') RETURNING id",
            (email, amount, method)
        )
        payment_id = cursor.fetchone()['id']
        
        # 2. Buscar usuário existente
        cursor.execute("SELECT id, wallet_address, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        user_created = False
        wallet_address = None
        user_id = None
        
        if not user:
            # ✅ CORREÇÃO: Criar usuário com senha temporária
            private_key, wallet_address = generate_polygon_wallet()
            
            # Gerar senha temporária única
            temp_password = f"temp_{secrets.token_hex(8)}"
            hashed_password = generate_password_hash(temp_password)
            
            # Criar nickname baseado no email
            nickname = f"User_{email.split('@')[0]}"
            
            cursor.execute(
                "INSERT INTO users (email, password, nickname, wallet_address, private_key) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (email, hashed_password, nickname, wallet_address, private_key)
            )
            user_id = cursor.fetchone()['id']
            user_created = True
            print(f"👤 Usuário criado com senha temporária: {email}")
        else:
            user_id = user['id']
            wallet_address = user['wallet_address']
            print(f"👤 Usuário existente: {email} - ID: {user_id}")
        
        # 3. Verificar/criar saldo
        cursor.execute("SELECT user_id FROM balances WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO balances (user_id, available) VALUES (%s, %s)",
                (user_id, 0.0)
            )
            print(f"💰 Saldo criado para usuário {user_id}")
        
        # 4. ✅ CORREÇÃO: NUNCA creditar automaticamente - SEMPRE PENDENTE
        # Apenas vincular usuário ao pagamento
        cursor.execute(
            "UPDATE payments SET user_id = %s WHERE id = %s",
            (user_id, payment_id)
        )
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Compra processada com sucesso! Aguarde a confirmação do pagamento.",
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

# 🔄 Rota para Admin do Site - CORRIGIDA
@app.route('/api/site/admin/payments', methods=['GET'])
def site_admin_payments():
    """Listar pagamentos para o admin do site"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        if not admin_token or admin_token != expected_token:
            return jsonify({"error": "Token inválido"}), 401
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
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
        print(f"❌ Erro: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# 🔄 Rota para estatísticas do admin do site
@app.route('/api/site/admin/stats', methods=['GET'])
def site_admin_stats():
    """Estatísticas para o admin do site"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        if not admin_token or admin_token != expected_token:
            return jsonify({"error": "Token inválido"}), 401
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
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
        print(f"❌ Erro stats: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# 🔄 Processar Pagamentos PIX Manualmente (Admin)
@app.route('/api/site/admin/process-payments', methods=['POST'])
def site_admin_process_payments():
    """Processar pagamentos PIX manualmente"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        if not admin_token or admin_token != expected_token:
            return jsonify({"error": "Token inválido"}), 401
        
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
                    "SELECT id, email, amount, user_id FROM payments WHERE id = %s AND status = 'pending'",
                    (payment_id,)
                )
                payment = cursor.fetchone()
                
                if payment and payment['user_id']:
                    # Creditar tokens
                    cursor.execute(
                        "UPDATE balances SET available = available + %s WHERE user_id = %s",
                        (payment['amount'], payment['user_id'])
                    )
                    
                    # Registrar no ledger
                    cursor.execute(
                        "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                        (payment['user_id'], 'ALZ', payment['amount'], 'purchase', f'Compra PIX processada - Payment ID: {payment_id}')
                    )
                    
                    # Atualizar status do pagamento
                    cursor.execute(
                        "UPDATE payments SET status = 'completed', processed_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (payment_id,)
                    )
                    
                    processed_count += 1
                    print(f"✅ Tokens creditados para pagamento {payment_id}: {payment['amount']} ALZ")
            
            conn.commit()
            
            return jsonify({
                "success": True,
                "message": f"{processed_count} pagamentos processados com sucesso",
                "processed_count": processed_count
            }), 200
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Erro process-payments: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Erro geral process-payments: {e}")
        return jsonify({"error": str(e)}), 500

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
    # ✅ CORREÇÃO CRÍTICA: LISTA COMPLETA DE ROTAS PÚBLICAS
    public_routes = [
        "/health", 
        "/system/info",
        "/webhook/stripe", 
        "/webhook/nowpayments", 
        "/webhook/mercadopago",
        "/register", 
        "/login", 
        "/first-time-setup", 
        "/check-user",
        "/api/site/purchase",
        "/create-checkout-session",
        "/admin/login"
    ]
    
    # ✅ PERMITIR TODAS AS ROTAS DE ADMIN DO SITE E HEALTH
    if request.path.startswith("/api/site/admin") or request.path == "/health":
        return
        
    if request.method == "OPTIONS" or request.path in public_routes:
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

# Rota de health check
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Allianza Wallet Backend",
        "version": "1.0.0",
        "database": "Neon PostgreSQL",
        "stripe_available": STRIPE_AVAILABLE
    }), 200

# Rota para informações do sistema
@app.route('/system/info', methods=['GET'])
def system_info():
    return jsonify({
        "service": "Allianza Wallet Backend",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "webhooks": {
            "stripe": "/webhook/stripe",
            "nowpayments": "/webhook/nowpayments",
            "mercadopago": "/webhook/mercadopago"
        },
        "features": {
            "stripe_available": STRIPE_AVAILABLE,
            "neon_database": True
        },
        "cors_domains": [
            "http://localhost:5173",
            "https://allianza.tech", 
            "https://wallet.allianza.tech"
        ]
    }), 200

if __name__ == "__main__":
    print("🚀 INICIANDO SERVIDOR ALLIANZA WALLET BACKEND")
    print("=" * 60)
    print(f"🔑 Token Admin Site: {SITE_ADMIN_TOKEN}")
    print(f"🔐 Stripe Disponível: {STRIPE_AVAILABLE}")
    print("🌐 Rotas públicas:")
    print("   - GET  /health")
    print("   - GET  /system/info") 
    print("   - POST /api/site/purchase")
    print("   - POST /register, /login, /first-time-setup, /check-user")
    print("   - POST /create-checkout-session")
    print("🔐 Rotas admin (requer token):")
    print("   - GET  /api/site/admin/payments")
    print("   - GET  /api/site/admin/stats")
    print("   - POST /api/site/admin/process-payments")
    print("📞 Webhooks:")
    print("   - POST /webhook/stripe")
    print("   - POST /webhook/nowpayments")
    print("=" * 60)
    
    try:
        app.run(debug=True, port=5000, host='0.0.0.0')
    except Exception as e:
        print(f"❌ Erro ao iniciar o servidor Flask: {e}")
