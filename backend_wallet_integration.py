# backend_wallet_integration.py
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

# ✅ CARREGAR VARIÁVEIS DE AMBIENTE PRIMEIRO - CRÍTICO!
from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("🔧 DEBUG - VARIÁVEIS DE AMBIENTE")
print("=" * 60)
print(f"SITE_ADMIN_TOKEN: {os.getenv('SITE_ADMIN_TOKEN', 'NÃO ENCONTRADO')}")
print(f"STRIPE_SECRET_KEY: {'✅ ENCONTRADO' if os.getenv('STRIPE_SECRET_KEY') else '❌ NÃO ENCONTRADO'}")
print(f"NEON_DATABASE_URL: {'✅ ENCONTRADO' if os.getenv('NEON_DATABASE_URL') else '❌ NÃO ENCONTRADO'}")
print("=" * 60)

print("🔍 Verificando variáveis de ambiente:")
print(f"   STRIPE_SECRET_KEY: {'✅' if os.getenv('STRIPE_SECRET_KEY') else '❌'}")
print(f"   NEON_DATABASE_URL: {'✅' if os.getenv('NEON_DATABASE_URL') else '❌'}")
print(f"   SITE_ADMIN_TOKEN: {'✅' if os.getenv('SITE_ADMIN_TOKEN') else '❌'}")

# ✅ INSTALAÇÃO FORÇADA DO STRIPE
import sys
import subprocess

print("=" * 60)
print("🚀 INICIANDO CARREGAMENTO STRIPE")
print("=" * 60)

STRIPE_AVAILABLE = False
stripe = None

# ✅ VERIFICAR VARIÁVEIS PRIMEIRO
stripe_secret_key = os.getenv('STRIPE_SECRET_KEY')
print(f"🔍 Variável STRIPE_SECRET_KEY: {'✅ ENCONTRADA' if stripe_secret_key else '❌ NÃO ENCONTRADA'}")
if stripe_secret_key:
    print(f"   Chave: {stripe_secret_key[:20]}...")

# ✅ ESTRATÉGIA 1: Importação normal
try:
    import stripe
    print("✅ Stripe importado via import padrão")
    STRIPE_AVAILABLE = True
except ImportError as e:
    print(f"❌ Falha importação padrão: {e}")

# ✅ ESTRATÉGIA 2: Instalação forçada se necessário
if not STRIPE_AVAILABLE:
    print("🔄 Tentando instalação forçada do Stripe...")
    try:
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "stripe==8.0.0"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            import stripe
            STRIPE_AVAILABLE = True
            print("✅ Stripe instalado via subprocess")
        else:
            print(f"❌ Erro instalação: {result.stderr}")
    except Exception as e:
        print(f"❌ Falha instalação forçada: {e}")

# ✅ CONFIGURAÇÃO FINAL CORRIGIDA
if STRIPE_AVAILABLE:
    try:
        if stripe_secret_key:
            stripe.api_key = stripe_secret_key
            print("✅ Stripe configurado com sucesso!")
            print("🎉 STRIPE OPERACIONAL! Versão: 8.0.0")
        else:
            print("❌ STRIPE_SECRET_KEY não encontrada nas variáveis de ambiente")
            STRIPE_AVAILABLE = False
    except Exception as e:
        print(f"❌ Erro configuração Stripe: {e}")
        STRIPE_AVAILABLE = False
else:
    print("🔴 STRIPE NÃO DISPONÍVEL - Pagamentos com cartão desativados")

print(f"📊 STATUS FINAL STRIPE: {'✅ DISPONÍVEL' if STRIPE_AVAILABLE else '❌ INDISPONÍVEL'}")
print("=" * 60)

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

# ✅ CONFIGURAÇÃO CORS SIMPLIFICADA - SEM DUPLICAÇÃO
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:5173",        # Vite dev
            "http://localhost:5174",        # Vite dev (nova porta)
            "http://127.0.0.1:5173",        # Vite dev (IP local)
            "http://127.0.0.1:5174",        # Vite dev (IP local)
            "http://localhost:3000",        # Next.js dev
            "http://127.0.0.1:3000",        # Next.js dev (IP local)
            "https://allianza.tech",        # Site vitrine
            "https://www.allianza.tech",    # Site vitrine (www)
            "https://wallet.allianza.tech", # Wallet
            "https://www.wallet.allianza.tech" # Wallet (www)
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"],
        "allow_headers": [
            "Content-Type", 
            "Authorization", 
            "X-Requested-With",
            "X-Request-ID",
            "Accept",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers"
        ],
        "expose_headers": [
            "Content-Range",
            "X-Content-Range",
            "Content-Length",
            "Content-Type"
        ],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# 🔐 CONFIGURAÇÕES DE SEGURANÇA ADMIN
ADMIN_USERS = {
    os.getenv('ADMIN_USER_1', 'admin'): os.getenv('ADMIN_PASSWORD_1', 'admin123'),
}

# ✅ TOKEN CORRETO - IGUAL AO FRONTEND
ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET', 'super-secret-jwt-key-2024-allianza')
SITE_ADMIN_TOKEN = os.getenv('SITE_ADMIN_TOKEN', 'allianza_super_admin_2024_CdE25$$$')

# Configurações de Pagamento
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_default_secret_change_in_production')
NOWPAYMENTS_IPN_SECRET = os.getenv('NOWPAYMENTS_IPN_SECRET', 'rB4Ic28l8posIjXA4fx90GuGnHagAxEj')

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

# 🔄 ROTA PARA ENVIO MANUAL DE TOKENS (ADMIN)
@app.route('/api/site/admin/manual-token-send', methods=['POST'])
def site_admin_manual_token_send():
    """Enviar tokens manualmente para qualquer email"""
    try:
        auth_header = request.headers.get('Authorization', '')
        print(f"🔐 Header de autorização recebido: {auth_header}")
        
        if not auth_header.startswith('Bearer '):
            print("❌ Token não fornecido ou formato inválido")
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        print(f"🔑 Token recebido: {admin_token}")
        print(f"🔑 Token esperado: {expected_token}")
        
        if not admin_token or admin_token != expected_token:
            print("❌ Token inválido")
            return jsonify({"error": "Token inválido"}), 401
        
        print("✅ Token válido, processando requisição...")
        
        data = request.json
        email = data.get('email')
        amount = data.get('amount')
        description = data.get('description', 'Crédito administrativo manual')
        admin_user = data.get('admin_user', 'admin')
        
        if not email or not amount:
            return jsonify({"error": "Email e valor são obrigatórios"}), 400
        
        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({"error": "Valor deve ser positivo"}), 400
        except ValueError:
            return jsonify({"error": "Valor inválido"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("BEGIN")
            
            print(f"🔄 Processando envio manual: {email} - {amount} ALZ")
            
            # Verificar se o usuário existe
            cursor.execute('SELECT id, email FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            
            if not user:
                # Se o usuário não existe, criar um registro pendente na tabela payments
                cursor.execute('''
                    INSERT INTO payments (email, amount, method, status, description, metadata)
                    VALUES (%s, %s, 'manual', 'pending', %s, %s)
                    RETURNING id
                ''', (email, amount, description, {'admin_user': admin_user, 'type': 'manual_credit'}))
                
                payment_id = cursor.fetchone()['id']
                
                # Registrar log administrativo
                cursor.execute('''
                    INSERT INTO admin_logs (admin_user, action, description, target_id)
                    VALUES (%s, %s, %s, %s)
                ''', (admin_user, 'manual_token_send_pending', 
                      f'Crédito manual de {amount} ALZ para {email} (usuário não cadastrado)', 
                      payment_id))
                
                conn.commit()
                
                return jsonify({
                    'success': True,
                    'message': f'Crédito de {amount} ALZ aguardando cadastro do usuário {email}',
                    'payment_id': payment_id,
                    'user_status': 'pending_registration'
                })
            
            # Se o usuário existe, creditar diretamente
            user_id = user['id']
            
            # Atualizar saldo
            cursor.execute('''
                INSERT INTO balances (user_id, available, asset)
                VALUES (%s, %s, 'ALZ')
                ON CONFLICT (user_id) 
                DO UPDATE SET 
                    available = balances.available + EXCLUDED.available,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING available
            ''', (user_id, amount))
            
            new_balance = cursor.fetchone()['available']
            
            # Registrar no ledger
            cursor.execute('''
                INSERT INTO ledger_entries 
                (user_id, asset, amount, entry_type, description, idempotency_key)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (user_id, 'ALZ', amount, 'admin_credit', 
                  f'Crédito administrativo: {description}',
                  f'manual_credit_{user_id}_{int(datetime.utcnow().timestamp())}'))
            
            # Registrar log administrativo
            cursor.execute('''
                INSERT INTO admin_logs (admin_user, action, description, target_id)
                VALUES (%s, %s, %s, %s)
            ''', (admin_user, 'manual_token_send', 
                  f'Crédito manual de {amount} ALZ para {email}', 
                  user_id))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': f'Crédito de {amount} ALZ enviado com sucesso para {email}',
                'new_balance': float(new_balance),
                'user_status': 'existing_user'
            })
            
        except Exception as e:
            conn.rollback()
            print(f'❌ Erro no envio manual de tokens: {e}')
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            conn.close()
            
    except Exception as e:
        print(f'❌ Erro geral manual-token-send: {e}')
        return jsonify({'error': str(e)}), 500

# 💳 ROTA PARA CRIAR SESSÃO STRIPE - VERSÃO CORRIGIDA DEFINITIVA
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """Criar sessão de checkout Stripe - VERSÃO CORRIGIDA"""
    print(f"🔧 Recebida requisição para criar sessão Stripe")
    
    if not STRIPE_AVAILABLE:
        print("❌ Stripe não disponível no backend")
        return jsonify({
            'error': 'Stripe não disponível no servidor',
            'stripe_available': False,
            'details': 'Serviço de pagamento com cartão temporariamente indisponível'
        }), 503
        
    try:
        data = request.json
        amount = data.get('amount')
        email = data.get('email')
        currency = data.get('currency', 'brl')
        
        print(f"📦 Dados recebidos: amount={amount}, email={email}, currency={currency}")
        
        if not amount or not email:
            print("❌ Dados incompletos")
            return jsonify({'error': 'Amount e email são obrigatórios'}), 400
        
        # Validar amount
        try:
            amount_int = int(amount)
            if amount_int <= 0:
                return jsonify({'error': 'Amount deve ser maior que zero'}), 400
            if amount_int < 50:
                return jsonify({'error': 'Valor mínimo é R$ 0,50'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Amount deve ser um número válido'}), 400
        
        print(f"💳 Criando sessão Stripe: {email} - {amount_int} centavos")
        
        # ✅ VERIFICAÇÃO EXTRA DE SEGURANÇA
        if not stripe or not hasattr(stripe, 'checkout'):
            print("❌ Módulo Stripe não carregado corretamente")
            return jsonify({'error': 'Módulo Stripe não carregado'}), 503
            
        if not stripe.api_key:
            print("❌ Chave do Stripe não configurada")
            return jsonify({'error': 'Chave do Stripe não configurada'}), 503
        
        # Criar sessão de checkout
        try:
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': currency.lower(),
                        'product_data': {
                            'name': 'Allianza Tokens (ALZ)',
                            'description': 'Compra de tokens ALZ para a plataforma Allianza'
                        },
                        'unit_amount': amount_int,
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url='https://allianza.tech/success',
                cancel_url='https://allianza.tech/cancel',
                customer_email=email,
                metadata={
                    'email': email, 
                    'amount_brl': amount_int / 100,
                    'source': 'allianza_site',
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            print(f"✅ Sessão Stripe criada com sucesso: {session.id}")
            print(f"🌐 URL do Checkout: {session.url}")
            
            return jsonify({
                'id': session.id,
                'url': session.url,
                'success': True,
                'message': 'Sessão de pagamento criada com sucesso'
            })
            
        except stripe.error.StripeError as stripe_error:
            print(f"❌ Erro do Stripe: {stripe_error}")
            error_message = str(stripe_error)
            if "api_key" in error_message.lower():
                error_message = "Erro de configuração do Stripe. Verifique as chaves de API."
            return jsonify({
                'error': f'Erro do Stripe: {error_message}',
                'stripe_error_type': type(stripe_error).__name__
            }), 400
            
    except Exception as e:
        print(f"❌ Erro inesperado ao criar sessão Stripe: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': f'Erro interno do servidor: {str(e)}',
            'details': 'Tente novamente em alguns instantes'
        }), 500

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
            amount = payment_intent['amount'] / 100
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
        received_signature = request.headers.get('x-nowpayments-ipn-signature')
        payload = request.get_data(as_text=True)
        
        print(f"📥 Webhook NowPayments recebido")
        
        if not received_signature:
            print("❌ Assinatura IPN não fornecida")
            return jsonify({'error': 'Missing signature'}), 401
        
        expected_signature = hmac.new(
            bytes(NOWPAYMENTS_IPN_SECRET, 'utf-8'),
            msg=bytes(payload, 'utf-8'),
            digestmod=hashlib.sha512
        ).hexdigest()
        
        if not hmac.compare_digest(received_signature, expected_signature):
            print("❌ Assinatura IPN inválida")
            return jsonify({'error': 'Invalid signature'}), 401
        
        data = request.json
        print(f"📊 Dados NowPayments: {data}")
        
        payment_status = data.get('payment_status')
        if payment_status in ['finished', 'confirmed']:
            email = data.get('customer_email') or data.get('buyer_email')
            amount = float(data.get('pay_amount', 0))
            payment_id = data.get('payment_id')
            
            if email and amount > 0:
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

# 🔑 Login Admin
@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Credenciais necessárias"}), 400
    
    if username in ADMIN_USERS and ADMIN_USERS[username] == password:
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

# 🔄 Rota para o Site processar pagamentos
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
            private_key, wallet_address = generate_polygon_wallet()
            temp_password = f"temp_{secrets.token_hex(8)}"
            hashed_password = generate_password_hash(temp_password)
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

# 🔄 Rota para Admin do Site
@app.route('/api/site/admin/payments', methods=['GET'])
def site_admin_payments():
    """Listar pagamentos para o admin do site"""
    try:
        auth_header = request.headers.get('Authorization', '')
        print(f"🔐 Header de autorização recebido: {auth_header}")
        
        if not auth_header.startswith('Bearer '):
            print("❌ Token não fornecido ou formato inválido")
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        print(f"🔑 Token recebido: {admin_token}")
        print(f"🔑 Token esperado: {expected_token}")
        
        if not admin_token or admin_token != expected_token:
            print("❌ Token inválido")
            return jsonify({"error": "Token inválido"}), 401
        
        print("✅ Token válido, processando requisição...")
        
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
        
        cursor.execute("SELECT COUNT(*) as total_users FROM users")
        user_stats = cursor.fetchone()
        
        TOTAL_SUPPLY = 1000000000
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
                cursor.execute(
                    "SELECT id, email, amount, user_id FROM payments WHERE id = %s AND status = 'pending'",
                    (payment_id,)
                )
                payment = cursor.fetchone()
                
                if payment and payment['user_id']:
                    cursor.execute(
                        "UPDATE balances SET available = available + %s WHERE user_id = %s",
                        (payment['amount'], payment['user_id'])
                    )
                    
                    cursor.execute(
                        "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                        (payment['user_id'], 'ALZ', payment['amount'], 'purchase', f'Compra PIX processada - Payment ID: {payment_id}')
                    )
                    
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

# ===== ROTAS EXISTENTES DA WALLET =====
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
    public_routes = [
        "/health", 
        "/system/info",
        "/webhook/stripe", 
        "/webhook/nowpayments", 
        "/register", 
        "/login", 
        "/first-time-setup", 
        "/check-user",
        "/api/site/purchase",
        "/create-checkout-session",
        "/admin/login",
        "/debug/stripe"
    ]
    
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

# ✅ ROTA DE HEALTH CHECK CORRIGIDA - SEM ERROS
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Allianza Wallet Backend",
        "version": "1.0.0",
        "database": "Neon PostgreSQL",
        "stripe_available": STRIPE_AVAILABLE,
        "stripe_version": "8.0.0"
    }), 200

# ✅ Rota para informações do sistema
@app.route('/system/info', methods=['GET'])
def system_info():
    return jsonify({
        "service": "Allianza Wallet Backend",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "webhooks": {
            "stripe": "/webhook/stripe",
            "nowpayments": "/webhook/nowpayments"
        },
        "features": {
            "stripe_available": STRIPE_AVAILABLE,
            "stripe_version": "8.0.0",
            "neon_database": True
        },
        "cors_domains": [
            "http://localhost:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "https://allianza.tech", 
            "https://wallet.allianza.tech"
        ]
    }), 200

# ✅ ENDPOINT DE DIAGNÓSTICO STRIPE
@app.route('/debug/stripe', methods=['GET'])
def debug_stripe():
    return jsonify({
        'stripe_available': STRIPE_AVAILABLE,
        'stripe_installed': STRIPE_AVAILABLE,
        'stripe_version': "8.0.0",
        'api_key_configured': bool(stripe.api_key) if STRIPE_AVAILABLE else False,
        'env_key_exists': bool(os.getenv('STRIPE_SECRET_KEY')),
        'status': 'Operational' if STRIPE_AVAILABLE else 'Not Available'
    }), 200

# ✅ ROTAS PARA BALANCES E LEDGER
@app.route('/balances/me', methods=['GET'])
def get_balances_me():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token is missing or invalid"}), 401

        token = auth_header.split(" ")[1]
        user_id = get_user_id_from_token(token)

        if not user_id:
            return jsonify({"error": "Invalid authentication token"}), 401

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT available, locked, staking_balance FROM balances WHERE user_id = %s AND asset = 'ALZ'", (user_id,))
        balance_data = cursor.fetchone()
        
        balance = {
            "asset": "ALZ",
            "available_balance": 0.0,
            "locked_balance": 0.0,
            "staking_balance": 0.0,
            "total_balance": 0.0
        }
        
        if balance_data:
            balance["available_balance"] = float(balance_data["available"]) if balance_data["available"] else 0.0
            balance["locked_balance"] = float(balance_data["locked"]) if balance_data["locked"] else 0.0
            balance["staking_balance"] = float(balance_data["staking_balance"]) if balance_data["staking_balance"] else 0.0
            balance["total_balance"] = balance["available_balance"] + balance["staking_balance"]

        return jsonify({
            "balance": balance
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar saldo: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/ledger/history', methods=['GET'])
def get_ledger_history():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token is missing or invalid"}), 401

        token = auth_header.split(" ")[1]
        user_id = get_user_id_from_token(token)

        if not user_id:
            return jsonify({"error": "Invalid authentication token"}), 401

        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, asset, amount, entry_type, description, created_at 
            FROM ledger_entries 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT %s OFFSET %s
        ''', (user_id, limit, offset))
        
        entries = cursor.fetchall()
        
        return jsonify([dict(entry) for entry in entries]), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar histórico do ledger: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    print("🚀 INICIANDO SERVIDOR ALLIANZA WALLET BACKEND")
    print("=" * 60)
    print(f"🔑 Token Admin Site: {SITE_ADMIN_TOKEN}")
    print(f"🔐 Stripe Disponível: {STRIPE_AVAILABLE}")
    
    if STRIPE_AVAILABLE:
        print("📦 Versão do Stripe: 8.0.0")
    
    print("🌐 Rotas públicas:")
    print("   - GET  /health")
    print("   - GET  /system/info") 
    print("   - POST /api/site/purchase")
    print("   - POST /register, /login, /first-time-setup, /check-user")
    print("   - POST /create-checkout-session")
    print("   - GET  /debug/stripe")
    print("   - POST /api/site/admin/manual-token-send")
    print("🔐 Rotas admin (requer token):")
    print("   - GET  /api/site/admin/payments")
    print("   - GET  /api/site/admin/stats")
    print("   - POST /api/site/admin/process-payments")
    print("📞 Webhooks:")
    print("   - POST /webhook/stripe")
    print("   - POST /webhook/nowpayments")
    print("💰 Rotas protegidas:")
    print("   - GET  /balances/me")
    print("   - GET  /ledger/history")
    print("=" * 60)
    
    try:
        app.run(debug=True, port=5000, host='0.0.0.0')
    except Exception as e:
        print(f"❌ Erro ao iniciar o servidor Flask: {e}")
