# backend_wallet_integration.py - PRODUÇÃO (ATUALIZADO COM STAKING)
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import time
import jwt
import requests
from functools import wraps
import hmac
import hashlib
import secrets
import json

# ✅ CARREGAR VARIÁVEIS DE AMBIENTE PRIMEIRO
from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("🚀 ALLIANZA WALLET BACKEND - PRODUÇÃO")
print("✅ VALORES CORRIGIDOS - 1 ALZ = R$ 0.10")
print("🎯 R$ 10,00 = 100 ALZ")
print("=" * 60)

# ✅ CONFIGURAÇÃO NOWPAYMENTS COM FALLBACK
NOWPAYMENTS_IPN_SECRET = os.getenv('NOWPAYMENTS_IPN_SECRET', 'rB4Ic28l8posIjXA4fx90GuGnHagAxEj')

print(f"🔑 NOWPAYMENTS_IPN_SECRET: {'✅ CONFIGURADO' if os.getenv('NOWPAYMENTS_IPN_SECRET') else '⚠️ USANDO FALLBACK'}")
print(f"📏 Comprimento: {len(NOWPAYMENTS_IPN_SECRET)} caracteres")
print(f"🔗 Webhook URL: https://allianza-wallet-backend.onrender.com/webhook/nowpayments" )
print(f"💳 STRIPE_SECRET_KEY: {'✅ PRODUÇÃO' if os.getenv('STRIPE_SECRET_KEY', '').startswith('sk_live_') else '❌ NÃO ENCONTRADO'}")
print(f"🗄️  NEON_DATABASE_URL: {'✅ CONFIGURADO' if os.getenv('NEON_DATABASE_URL') else '❌ NÃO ENCONTRADO'}")
print("=" * 60)

# ✅ INSTALAÇÃO FORÇADA DO STRIPE
import sys
import subprocess

STRIPE_AVAILABLE = False
stripe = None

# ✅ VERIFICAR VARIÁVEIS PRIMEIRO
stripe_secret_key = os.getenv('STRIPE_SECRET_KEY')

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

# ✅ CONFIGURAÇÃO FINAL CORRIGIDA - PRODUÇÃO
if STRIPE_AVAILABLE:
    try:
        if stripe_secret_key:
            stripe.api_key = stripe_secret_key
            if stripe_secret_key.startswith('sk_live_'):
                print("🎉 STRIPE EM MODO PRODUÇÃO! Pagamentos reais ativados!")
            else:
                print("🔧 STRIPE EM MODO TESTE")
            print("📦 Versão Stripe: 8.0.0")
        else:
            print("❌ STRIPE_SECRET_KEY não encontrada")
            STRIPE_AVAILABLE = False
    except Exception as e:
        print(f"❌ Erro configuração Stripe: {e}")
        STRIPE_AVAILABLE = False
else:
    print("🔴 STRIPE NÃO DISPONÍVEL - Pagamentos com cartão desativados")

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

# ✅ CONFIGURAÇÃO CORS COMPLETA PARA PRODUÇÃO E DESENVOLVIMENTO
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://allianza.tech",
            "https://admin.allianza.tech",
            "https://www.allianza.tech", 
            "https://wallet.allianza.tech",
            "https://www.wallet.allianza.tech",
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "http://localhost:5175",
            "http://127.0.0.1:5175"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"],
        "allow_headers": [
            "Content-Type", 
            "Authorization", 
            "X-Requested-With",
            "Accept",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers"
        ],
        "expose_headers": ["Content-Range", "X-Content-Range"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# ✅ ROTAS OPTIONS PARA CORS PREFLIGHT
@app.route('/api/site/admin/payments', methods=['OPTIONS'])
@app.route('/api/site/admin/stats', methods=['OPTIONS'])
@app.route('/api/site/admin/process-payments', methods=['OPTIONS']) 
@app.route('/api/site/admin/manual-token-send', methods=['OPTIONS'])
@app.route('/api/site/admin/debug-token', methods=['OPTIONS'])
@app.route('/api/site/admin/create-staking-table', methods=['OPTIONS'])
@app.route('/api/site/admin/check-tables', methods=['OPTIONS'])
@app.route('/health', methods=['OPTIONS'])
@app.route('/api/site/purchase', methods=['OPTIONS'])
@app.route('/create-checkout-session', methods=['OPTIONS'])
@app.route('/webhook/nowpayments', methods=['OPTIONS'])
@app.route('/api/nowpayments/check-config', methods=['OPTIONS'])
@app.route('/api/nowpayments/test-webhook', methods=['OPTIONS'])

def options_handler():
    return '', 200

# 🔐 CONFIGURAÇÕES DE SEGURANÇA ADMIN - PRODUÇÃO (CORRIGIDO)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD_1', 'CdE25$$$')
ADMIN_USERS = {
    'admin': ADMIN_PASSWORD,
}

# ✅ TOKEN CORRETO - PRODUÇÃO (FORCE O TOKEN CORRETO)
ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET', 'super-secret-jwt-key-2024-allianza-prod')
SITE_ADMIN_TOKEN = 'allianza_super_admin_2024_CdE25$$$'  # ✅ FORCE 34 CARACTERES

# Configurações de Pagamento - PRODUÇÃO
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_default_secret_change_in_production')

# ✅ DEBUG DAS VARIÁVEIS DE AMBIENTE (CORRIGIDO)
print("🎯 VERIFICAÇÃO DAS VARIÁVEIS:")
print(f"🔑 SITE_ADMIN_TOKEN: '{SITE_ADMIN_TOKEN}'")
print(f"📏 Comprimento: {len(SITE_ADMIN_TOKEN)}")
print(f"🔐 ADMIN_JWT_SECRET: '{ADMIN_JWT_SECRET}'")
print(f"👤 ADMIN_PASSWORD: '{ADMIN_PASSWORD}'")
print(f"🔗 NOWPAYMENTS_IPN_SECRET: '{NOWPAYMENTS_IPN_SECRET}' ({len(NOWPAYMENTS_IPN_SECRET)} chars)")
print("=" * 60)

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

# 🔄 FUNÇÃO PARA PROCESSAR PAGAMENTOS AUTOMATICAMENTE (CORRIGIDA - VALORES ALINHADOS)
def process_automatic_payment(email, amount_alz, method, external_id):
    """Processar pagamento automaticamente e creditar tokens COM VALORES CORRETOS"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("BEGIN")
        
        print(f"🔄 Processando pagamento automático: {email} - {amount_alz} ALZ - {method}")
        print(f"💰 Valor a creditar: {amount_alz} ALZ")
        
        # ✅ CORREÇÃO: Registrar o valor EM ALZ diretamente
        # O valor em BRL para registro é calculado como: ALZ * 0.10
        brl_amount_for_db = float(amount_alz) * 0.10
        
        # Registrar pagamento com metadata correto
        cursor.execute(
            "INSERT INTO payments (email, amount, method, status, tx_hash, metadata) VALUES (%s, %s, %s, 'completed', %s, %s) RETURNING id",
            (email, brl_amount_for_db, method, external_id, json.dumps({'alz_amount': float(amount_alz)}))
        )
        payment_id = cursor.fetchone()['id']
        print(f"✅ Pagamento registrado: ID {payment_id} - {amount_alz} ALZ = R$ {brl_amount_for_db}")
        
        # Buscar ou criar usuário
        cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        user_created = False
        wallet_address = None
        user_id = None
        
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
        
        # ✅ CORREÇÃO: Creditar o valor CORRETO em ALZ (sem multiplicar por 10)
        cursor.execute(
            "UPDATE balances SET available = available + %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
            (amount_alz, user_id)  # Usar o amount original (em ALZ)
        )
        print(f"💰 Saldo atualizado: +{amount_alz} ALZ para user {user_id}")
        
        # Registrar entrada no ledger
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description, idempotency_key) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (user_id, 'ALZ', amount_alz, 'purchase', payment_id, f'Compra via {method}', f'purchase_{payment_id}')
        )
        print(f"✅ Entrada no ledger registrada para payment {payment_id}")

        # ✅ COMPENSAÇÃO DE TAXAS PARA CRIPTO (usando valor correto)
        if method == 'crypto':
            bonus_amount = float(amount_alz) * 0.02  # 2% do valor em ALZ
            
            cursor.execute(
                "UPDATE balances SET available = available + %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                (bonus_amount, user_id)
            )
            cursor.execute(
                "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description, idempotency_key) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (user_id, 'ALZ', bonus_amount, 'fee_compensation', payment_id, '🎁 Bônus compensação de taxa crypto', f'fee_comp_{payment_id}')
            )
            print(f"🎁 Bônus aplicado para {email}: +{bonus_amount} ALZ")

        cursor.execute("COMMIT")
        return {"success": True, "user_created": user_created, "wallet_address": wallet_address}

    except Exception as e:
        cursor.execute("ROLLBACK")
        print(f"❌ Erro ao processar pagamento automático: {e}")
        return {"success": False, "error": str(e)}
    finally:
        conn.close()

# 🔒 Middleware de Autenticação
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization token is missing or invalid"}), 401

        token = auth_header.split(" ")[1]
        user_id = get_user_id_from_token(token)

        if not user_id:
            return jsonify({"error": "Invalid authentication token"}), 401
        
        request.user_id = user_id
        return f(*args, **kwargs)
    return decorated_function

# 🛒 ROTA DE COMPRA (USADA PELO FRONTEND) - CORREÇÃO CRÍTICA
@app.route('/api/site/purchase', methods=['POST'])
def site_purchase():
    """Registrar uma compra de ALZ - CORREÇÃO URGENTE DOS VALORES"""
    data = request.json
    email = data.get('email')
    amount = data.get('amount') # Este é o valor em BRL (do frontend)
    method = data.get('method')
    sourceName = data.get('sourceName')  # Para PIX
    
    if not email or not amount or not method:
        return jsonify({"error": "Email, amount e method são obrigatórios"}), 400
    
    try:
        amount_brl = float(amount)  # Valor em BRL
    except ValueError:
        return jsonify({"error": "Valor (amount) inválido"}), 400
    
    if amount_brl <= 0:
        return jsonify({"error": "Valor (amount) deve ser positivo"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("BEGIN")
        
        # ✅✅✅ CORREÇÃO CRÍTICA: Calcular valor em ALZ CORRETAMENTE
        # 1 ALZ = R$ 0,10, então: ALZ = BRL / 0.10
        amount_alz = amount_brl / 0.10  # R$ 10,00 / 0.10 = 100 ALZ ✅
        brl_amount_for_db = amount_brl  # 10.0 (BRL)
        
        # ✅ DEBUG PARA VERIFICAR VALORES
        print(f"🔢 DEBUG VALORES: R$ {amount_brl} → {amount_alz} ALZ | BRL no DB: {brl_amount_for_db}")
        
        # Preparar metadata
        metadata = {'alz_amount': float(amount_alz)}
        if sourceName:
            metadata['source_name'] = sourceName
        
        # ✅ Registrar o valor EM BRL no banco, mas com metadata correto
        cursor.execute(
            "INSERT INTO payments (email, amount, method, status, metadata) VALUES (%s, %s, %s, 'pending', %s) RETURNING id",
            (email, brl_amount_for_db, method, json.dumps(metadata))
        )
        payment_id = cursor.fetchone()['id']
        
        print(f"✅ Compra registrada: ID {payment_id} | R$ {brl_amount_for_db} = {amount_alz} ALZ")
        
        # Buscar usuário existente
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
        
        # Verificar/criar saldo
        cursor.execute("SELECT user_id FROM balances WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO balances (user_id, available) VALUES (%s, %s)",
                (user_id, 0.0)
            )
            print(f"💰 Saldo criado para usuário {user_id}")
        
        # Atualizar o registro de pagamento com o user_id
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
            "user_id": user_id,
            "calculated_alz": amount_alz,  # ✅ Para debug
            "received_brl": amount_brl    # ✅ Para debug
        }), 200
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro no processamento da compra: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 💳 ROTA PARA CRIAR SESSÃO STRIPE - PRODUÇÃO (CORRIGIDA)
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """Criar sessão de checkout Stripe - PRODUÇÃO COM VALORES CORRETOS"""
    
    if not STRIPE_AVAILABLE:
        return jsonify({
            'error': 'Stripe não disponível no servidor',
            'stripe_available': False
        }), 503
        
    try:
        data = request.json
        amount_brl_cents = data.get('amount')  # Valor em centavos de BRL (ex: R$ 0,10 = 10 centavos)
        email = data.get('email')
        currency = data.get('currency', 'brl')
        
        if not amount_brl_cents or not email:
            return jsonify({"error": "Valor e email são obrigatórios"}), 400
            
        # ✅ CORREÇÃO: Calcular valor em ALZ corretamente
        # amount_brl_cents é o valor em centavos de BRL (ex: 10 centavos = R$ 0,10)
        amount_brl = amount_brl_cents / 100  # Converter para BRL
        # O valor em ALZ é calculado como: BRL / 0.10 (1 ALZ = R$ 0.10)
        amount_alz = amount_brl / 0.10  # Converter para ALZ (1 ALZ = R$ 0,10)
        
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': currency,
                    'product_data': {
                        'name': 'Tokens Allianza (ALZ)',
                    },
                    'unit_amount': amount_brl_cents,  # Valor em centavos
                },
                'quantity': 1,
            }],
            mode='payment',
            customer_email=email,
            success_url=request.url_root + 'success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.url_root + 'cancel',
            metadata={
                'email': email,
                'amount_brl': amount_brl,
                'amount_alz': amount_alz,
                'method': 'stripe'
            }
        )
        
        return jsonify({'url': session.url})
        
    except Exception as e:
        print(f"❌ Erro ao criar sessão Stripe: {e}")
        return jsonify({'error': str(e)}), 500

# 🎣 WEBHOOK STRIPE (CORRIGIDO)
@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Receber eventos do Stripe - COM VALORES CORRETOS"""
    if not STRIPE_AVAILABLE:
        return jsonify({'error': 'Stripe not available'}), 503
        
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return 'Invalid signature', 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        email = session.get('customer_email')
        metadata = session.get('metadata', {})
        amount_alz = metadata.get('amount_alz')
        
        if email and amount_alz:
            try:
                amount_alz = float(amount_alz)
                result = process_automatic_payment(email, amount_alz, 'stripe', session.id)
                if result['success']:
                    print(f"✅ Pagamento Stripe processado com sucesso para {email}. {amount_alz} ALZ creditados.")
                else:
                    print(f"❌ Falha ao creditar tokens para {email}: {result['error']}")
            except Exception as e:
                print(f"❌ Erro ao processar pagamento Stripe: {e}")

    return 'OK', 200

# 🔑 FUNÇÕES AUXILIARES NOWPAYMENTS
def verify_nowpayments_signature(payload, signature):
    """Verifica a assinatura IPN da NowPayments"""
    if not signature:
        return False
        
    # O payload deve ser os bytes brutos da requisição
    # A chave secreta deve ser convertida para bytes
    secret_bytes = NOWPAYMENTS_IPN_SECRET.encode('utf-8')
    
    # Calcular o HMAC-SHA512
    calculated_signature = hmac.new(
        secret_bytes, 
        payload, 
        hashlib.sha512
    ).hexdigest()
    
    return calculated_signature == signature

def extract_nowpayments_data(data):
    """Extrai dados relevantes do payload da NowPayments"""
    try:
        # Status do pagamento
        payment_status = data.get('payment_status')
        payment_id = data.get('payment_id') or data.get('invoice_id')
        
        # Email. Tenta extrair de vários campos
        email = (
            data.get('order_description') or
            data.get('customer_email') or
            data.get('email') or
            extract_email_from_string(data.get('order_id', '')) or
            extract_email_from_string(data.get('description', '')))
        
        # Valores - usar pay_amount ou actually_paid
        pay_amount = float(data.get('pay_amount', 0))
        actually_paid = float(data.get('actually_paid', 0))
        invoice_amount = float(data.get('invoice_amount', 0))
        
        # ✅ CORREÇÃO: Lógica de amount priorizada
        if actually_paid > 0:
            final_amount = actually_paid
        elif pay_amount > 0:
            final_amount = pay_amount
        else:
            final_amount = invoice_amount
            
        currency = data.get('pay_currency') or data.get('currency', 'usdt')
        
        return {
            'payment_status': payment_status,
            'payment_id': payment_id,
            'email': email,
            'amount': final_amount,
            'currency': currency,
            'actually_paid': actually_paid,
            'pay_amount': pay_amount,
            'raw_data': data
        }
        
    except Exception as e:
        print(f"❌ Erro extração dados: {e}")
        return None

def extract_email_from_string(text):
    """Tenta extrair email de string"""
    import re
    if not text:
        return None
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', str(text))
    return email_match.group() if email_match else None

# ✅ WEBHOOK NOWPAYMENTS CORRIGIDO - URL COMPLETA
@app.route('/webhook/nowpayments', methods=['POST', 'GET'])
def nowpayments_webhook():
    """Webhook NowPayments - COM VALORES CORRETOS"""
    try:
        print("=" * 70)
        print("🎯 NOWPAYMENTS WEBHOOK CHAMADO - VALORES CORRETOS")
        print("=" * 70)
        
        # Se for GET, retorna status (para teste)
        if request.method == 'GET':
            return jsonify({
                "status": "active", 
                "message": "NowPayments webhook está operacional",
                "webhook_url": "https://allianza-wallet-backend.onrender.com/webhook/nowpayments",
                "method": "POST",
                "ipn_secret_length": len(NOWPAYMENTS_IPN_SECRET ),
                "timestamp": datetime.now().isoformat()
            }), 200
        
        # ✅ CORREÇÃO: Obter payload como BYTES
        payload_bytes = request.get_data()
        received_signature = request.headers.get('x-nowpayments-ipn-signature')
        
        print(f"📍 URL Recebida: {request.url}")
        print(f"📧 Host: {request.headers.get('Host')}")
        print(f"🔑 Assinatura: {received_signature}")
        print(f"📦 Tamanho do payload: {len(payload_bytes)} bytes")
        print(f"🔐 IPN Secret length: {len(NOWPAYMENTS_IPN_SECRET)}")
        
        # ✅ CORREÇÃO: Verificar assinatura com bytes
        if not verify_nowpayments_signature(payload_bytes, received_signature):
            print("❌ Assinatura inválida!")
            return jsonify({'error': 'Invalid signature', 'received_signature': received_signature}), 401
        
        print("✅ Assinatura válida! Processando payload...")
        
        # ✅ CORREÇÃO: Parse JSON
        try:
            data = json.loads(payload_bytes.decode('utf-8'))
        except json.JSONDecodeError as e:
            print(f"❌ JSON inválido: {e}")
            print(f"📄 Payload raw: {payload_bytes.decode('utf-8', errors='ignore')}")
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # ✅ CORREÇÃO: Extrair dados estruturados
        payment_data = extract_nowpayments_data(data)
        if not payment_data:
            return jsonify({'error': 'Invalid payload structure'}), 400
        
        payment_status = payment_data['payment_status']
        email = payment_data['email']
        amount = payment_data['amount'] # Este é o valor em cripto (ex: BTC, USDT)
        payment_id = payment_data['payment_id']
        
        print(f"📊 Status do pagamento: {payment_status}")
        print(f"📧 Email identificado: {email}")
        print(f"💰 Valor: {amount} ({payment_data['currency']})")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # 1. Buscar o registro de pagamento inicial
            cursor.execute("SELECT id, amount, metadata FROM payments WHERE id = %s", (payment_id,))
            db_payment = cursor.fetchone()
            
            if not db_payment:
                # Tenta buscar pelo tx_hash (caso seja o segundo webhook)
                cursor.execute("SELECT id, amount, metadata FROM payments WHERE tx_hash = %s", (payment_id,))
                db_payment = cursor.fetchone()
                
            if not db_payment:
                print(f"⚠️ Pagamento ID {payment_id} não encontrado no DB. Ignorando.")
                return 'Payment not found', 200
                
            db_payment_id = db_payment['id']
            db_metadata = db_payment['metadata']
            
            # 2. Processar status
            if payment_status in ['finished', 'sending', 'partially_paid', 'fully_paid', 'confirmed']:
                # Statuses que indicam pagamento bem-sucedido ou em progresso
                
                # Verifica se já foi processado
                cursor.execute("SELECT status FROM payments WHERE id = %s", (db_payment_id,))
                current_status = cursor.fetchone()['status']
                
                if current_status == 'completed':
                    print(f"✅ Pagamento ID {db_payment_id} já está COMPLETED. Ignorando evento.")
                    return 'Already completed', 200
                
                # Se o status for 'finished' ou 'fully_paid', processa o crédito de ALZ
                if payment_status in ['finished', 'fully_paid', 'confirmed']:
                    
                    # ✅ CORREÇÃO: Usar o valor em ALZ que foi salvo no metadata
                    alz_amount_to_credit = db_metadata.get('alz_amount')
                    
                    if not alz_amount_to_credit:
                        print(f"❌ Metadata 'alz_amount' não encontrado para ID {db_payment_id}. Não é possível creditar.")
                        return 'Missing ALZ amount', 400
                        
                    alz_amount_to_credit = float(alz_amount_to_credit)
                    
                    # 3. Processar pagamento automático (creditar ALZ)
                    result = process_automatic_payment(email, alz_amount_to_credit, 'crypto', payment_id)
                    
                    if result['success']:
                        # 4. Atualizar status do pagamento para 'completed'
                        cursor.execute(
                            "UPDATE payments SET status = 'completed', tx_hash = %s, processed_at = %s WHERE id = %s",
                            (payment_id, datetime.utcnow(), db_payment_id)
                        )
                        conn.commit()
                        print(f"🎉 Pagamento ID {db_payment_id} COMPLETED. {alz_amount_to_credit} ALZ creditados.")
                        return 'Payment completed and tokens credited', 200
                    else:
                        # Falha ao creditar tokens (erro de DB)
                        print(f"❌ Falha ao creditar tokens para ID {db_payment_id}: {result['error']}")
                        return 'Token credit failure', 500
                        
                else:
                    # Outros status de progresso (sending, partially_paid)
                    cursor.execute(
                        "UPDATE payments SET status = %s, tx_hash = %s WHERE id = %s",
                        (payment_status, payment_id, db_payment_id)
                    )
                    conn.commit()
                    print(f"🔄 Pagamento ID {db_payment_id} atualizado para status: {payment_status}")
                    return 'Status updated', 200
                    
            elif payment_status in ['failed', 'expired', 'refunded']:
                # Statuses de falha
                cursor.execute(
                    "UPDATE payments SET status = %s, tx_hash = %s WHERE id = %s",
                    (payment_status, payment_id, db_payment_id)
                )
                conn.commit()
                print(f"🔴 Pagamento ID {db_payment_id} falhou/expirou. Status: {payment_status}")
                return 'Payment failed', 200
            
            else:
                # Status desconhecido
                print(f"❓ Status desconhecido: {payment_status}. Ignorando.")
                return 'Unknown status', 200

        except Exception as e:
            conn.rollback()
            print(f"❌ Erro fatal no NowPayments Webhook: {e}")
            return 'Internal Server Error', 500
        finally:
            conn.close()

    except Exception as e:
        print(f"❌ Erro geral no NowPayments Webhook: {e}")
        return jsonify({'error': str(e)}), 500

# ✅ ROTA PARA CHECAR CONFIGURAÇÃO NOWPAYMENTS
@app.route('/api/nowpayments/check-config', methods=['GET'])
def check_nowpayments_config():
    """Verifica se as chaves da NowPayments estão configuradas"""
    return jsonify({
        "ipn_secret_configured": bool(NOWPAYMENTS_IPN_SECRET),
        "ipn_secret_length": len(NOWPAYMENTS_IPN_SECRET),
        "webhook_url": "https://allianza-wallet-backend.onrender.com/webhook/nowpayments",
        "status": "OK" if NOWPAYMENTS_IPN_SECRET else "MISSING_SECRET"
    } ), 200

# ✅ ROTA PARA TESTAR WEBHOOK NOWPAYMENTS (SIMULAÇÃO)
@app.route('/api/nowpayments/test-webhook', methods=['POST'])
def test_nowpayments_webhook():
    """Simula um evento de webhook da NowPayments (apenas para debug)"""
    try:
        data = request.json
        
        # Simula a assinatura (apenas para debug local, não use em produção)
        payload_bytes = json.dumps(data).encode('utf-8')
        secret_bytes = NOWPAYMENTS_IPN_SECRET.encode('utf-8')
        simulated_signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha512).hexdigest()
        
        # Envia a requisição para o próprio webhook
        response = requests.post(
            request.url_root + 'webhook/nowpayments',
            data=payload_bytes,
            headers={
                'Content-Type': 'application/json',
                'x-nowpayments-ipn-signature': simulated_signature
            }
        )
        
        return jsonify({
            "success": True,
            "message": "Webhook de teste enviado e processado.",
            "response_status": response.status_code,
            "response_text": response.text,
            "simulated_signature": simulated_signature
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 🔄 Rota para Admin do Site - PRODUÇÃO (COM DEBUG CORRIGIDO)
@app.route('/api/site/admin/payments', methods=['GET'])
def site_admin_payments():
    """Listar pagamentos para o admin do site - PRODUÇÃO CORRIGIDA"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
        print("=" * 50)
        print("🔐 ADMIN PAYMENTS - VERIFICAÇÃO DE TOKEN")
        print(f"📨 Header: {auth_header}")
        
        if not auth_header.startswith('Bearer '):
            print("❌ Header não começa com Bearer")
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        print(f"🔑 Token recebido: '{admin_token}'")
        print(f"🔑 Token esperado: '{expected_token}'")
        print(f"✅ São iguais? {admin_token == expected_token}")
        
        if not admin_token:
            print("❌ Token vazio")
            return jsonify({"error": "Token vazio"}), 401
            
        if admin_token != expected_token:
            print("❌ Tokens não coincidem!")
            print(f"   Recebido: '{admin_token}'")
            print(f"   Esperado: '{expected_token}'")
            print(f"   Comprimento recebido: {len(admin_token)}")
            print(f"   Comprimento esperado: {len(expected_token)}")
            return jsonify({"error": "Token inválido"}), 401
        
        print("✅ Token válido! Processando requisição...")
        print("=" * 50)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.id, p.email, p.amount, p.method, p.status, p.created_at, 
                   p.processed_at, u.wallet_address, u.nickname, p.metadata
            FROM payments p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        ''')
        payments = cursor.fetchall()
        
        print(f"✅ Retornando {len(payments)} pagamentos")
        
        # Converte o resultado para um formato JSON serializável
        data_list = []
        for payment in payments:
            payment_dict = dict(payment)
            # Converte valores numéricos (Decimal) para float para JSON
            payment_dict['amount'] = float(payment_dict['amount'])
            
            # ✅✅✅ CORREÇÃO CRÍTICA: NÃO DIVIDIR POR 0.10 NOVAMENTE!
            # O valor já está correto no metadata ou no amount
            if payment_dict['metadata'] and payment_dict['metadata'].get('alz_amount'):
                payment_dict['alz_amount'] = float(payment_dict['metadata']['alz_amount'])
                print(f"💰 Usando metadata: R$ {payment_dict['amount']} → {payment_dict['alz_amount']} ALZ")
            else:
                # ✅ CORREÇÃO: Usar o amount diretamente (já está em ALZ após processamento)
                payment_dict['alz_amount'] = float(payment_dict['amount'])
                print(f"💰 Usando amount direto: {payment_dict['alz_amount']} ALZ")
                
            # O metadata já é um JSONB, mas garantimos que seja um dict
            if payment_dict['metadata'] is None:
                payment_dict['metadata'] = {}
                
            data_list.append(payment_dict)

        return jsonify({
            "success": True,
            "data": data_list
        }), 200
        
    except Exception as e:
        print(f"❌ Erro em admin/payments: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# 🔄 Rota para estatísticas do admin do site - PRODUÇÃO
@app.route('/api/site/admin/stats', methods=['GET'])
def site_admin_stats():
    """Estatísticas para o admin do site - PRODUÇÃO"""
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

# 🔄 Processar Pagamentos PIX Manualmente (Admin) - CORREÇÃO CRÍTICA
@app.route('/api/site/admin/process-payments', methods=['POST'])
def site_admin_process_payments():
    """Processar pagamentos PIX manualmente - CORREÇÃO DOS VALORES"""
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
                    "SELECT id, email, amount, user_id, method, metadata FROM payments WHERE id = %s AND status = 'pending'",
                    (payment_id,)
                )
                payment = cursor.fetchone()
                
                if payment and payment['user_id']:
                    
                    # ✅✅✅ CORREÇÃO CRÍTICA: Calcular ALZ CORRETAMENTE
                    # O amount no banco está em BRL, então converter para ALZ
                    alz_amount_to_credit = float(payment['amount']) / 0.10  # R$ 20,00 / 0.10 = 200 ALZ
                    
                    # Se tiver metadata, usar o valor do metadata (que já deve estar correto)
                    if payment['metadata'] and payment['metadata'].get('alz_amount'):
                        alz_amount_to_credit = float(payment['metadata']['alz_amount'])
                        
                    print(f"💰 PROCESSANDO: R$ {payment['amount']} → {alz_amount_to_credit} ALZ para {payment['email']}")
                    
                    # Creditar o valor em ALZ
                    cursor.execute(
                        "UPDATE balances SET available = available + %s WHERE user_id = %s",
                        (alz_amount_to_credit, payment['user_id'])
                    )
                    
                    # Registrar no ledger
                    cursor.execute(
                        "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, related_id) VALUES (%s, %s, %s, %s, %s, %s)",
                        (payment['user_id'], 'ALZ', alz_amount_to_credit, 'purchase', f'Compra {payment["method"]} processada - Payment ID: {payment_id}', payment_id)
                    )
                    
                    # COMPENSAR TAXAS PARA CRIPTO
                    if payment['method'] == 'crypto':
                        bonus_amount = alz_amount_to_credit * 0.02
                        cursor.execute(
                            "UPDATE balances SET available = available + %s WHERE user_id = %s",
                            (bonus_amount, payment['user_id'])
                        )
                        cursor.execute(
                            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, related_id) VALUES (%s, %s, %s, %s, %s, %s)",
                            (payment['user_id'], 'ALZ', bonus_amount, 'fee_compensation', '🎁 Bônus compensação de taxa crypto', payment_id)
                        )
                        print(f"🎁 Bônus aplicado: +{bonus_amount} ALZ")
                    
                    # Atualizar status
                    cursor.execute(
                        "UPDATE payments SET status = 'completed', processed_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (payment_id,)
                    )
                    
                    processed_count += 1
                    print(f"✅ Tokens creditados: {alz_amount_to_credit} ALZ para pagamento {payment_id}")
            
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

# 🚀 ENVIO MANUAL DE TOKENS (ADMIN)
@app.route('/api/site/admin/manual-token-send', methods=['POST'])
def site_admin_manual_token_send():
    """Envio manual de tokens por administrador"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        if not admin_token or admin_token != expected_token:
            return jsonify({"error": "Token inválido"}), 401
        
        data = request.json
        email = data.get('email')
        amount = data.get('amount')
        description = data.get('description', 'Crédito administrativo manual')
        admin_user = data.get('admin_user', 'admin')
        
        if not email or not amount:
            return jsonify({"error": "Email e quantidade são obrigatórios"}), 400
        
        try:
            amount = float(amount)
        except ValueError:
            return jsonify({"error": "Quantidade inválida"}), 400
        
        if amount <= 0:
            return jsonify({"error": "Quantidade deve ser positiva"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("BEGIN")
            
            # Buscar usuário
            cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({"error": "Usuário não encontrado"}), 404
            
            user_id = user['id']
            
            # Verificar/criar saldo
            cursor.execute("SELECT user_id FROM balances WHERE user_id = %s", (user_id,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO balances (user_id, available) VALUES (%s, %s)",
                    (user_id, 0.0)
                )
            
            # Creditar tokens
            cursor.execute(
                "UPDATE balances SET available = available + %s, updated_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                (amount, user_id)
            )
            
            # Registrar no ledger
            cursor.execute(
                "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, idempotency_key) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, 'ALZ', amount, 'manual_credit', description, f'manual_{user_id}_{int(time.time())}')
            )
            
            # Registrar log administrativo
            cursor.execute(
                "INSERT INTO admin_logs (admin_user, action, description, target_id) VALUES (%s, %s, %s, %s)",
                (admin_user, 'manual_token_send', f'Enviou {amount} ALZ para {email}', user_id)
            )
            
            conn.commit()
            
            print(f"✅ Envio manual realizado: {amount} ALZ para {email}")
            
            return jsonify({
                "success": True,
                "message": f"{amount} ALZ enviados com sucesso para {email}",
                "amount": amount,
                "email": email
            }), 200
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Erro no envio manual: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Erro geral envio manual: {e}")
        return jsonify({"error": str(e)}), 500

# 🔧 ROTA PARA CRIAR TABELA STAKING MANUALMENTE
@app.route('/api/site/admin/create-staking-table', methods=['POST'])
def create_staking_table():
    """Criar tabela de staking manualmente"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token não fornecido"}), 401
        
        admin_token = auth_header.replace('Bearer ', '').strip()
        expected_token = SITE_ADMIN_TOKEN
        
        if not admin_token or admin_token != expected_token:
            return jsonify({"error": "Token inválido"}), 401
        
        # Executar a criação da tabela
        init_db()
        
        return jsonify({
            "success": True,
            "message": "Tabela de staking criada/verificada com sucesso!"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🔍 ROTA PARA VERIFICAR TABELAS
@app.route('/api/site/admin/check-tables', methods=['GET'])
def check_tables():
    """Verificar se a tabela stakes existe"""
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
        
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = 'stakes'
        """)
        
        table_exists = cursor.fetchone() is not None
        
        # Verificar também a estrutura da tabela
        if table_exists:
            cursor.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'stakes'
            """)
            columns = cursor.fetchall()
            column_names = [col['column_name'] for col in columns]
        
        return jsonify({
            "stakes_table_exists": table_exists,
            "columns": column_names if table_exists else [],
            "message": "Tabela de staking encontrada!" if table_exists else "Tabela de staking NÃO encontrada!"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ===== ROTAS EXISTENTES DA WALLET =====

# 🔄 Rota para Admin do Site - PRODUÇÃO (COM DEBUG)
def get_user_id_from_token(token):
    try:
        parts = token.split("_")
        if len(parts) >= 3 and parts[0] == "mock" and parts[1] == "token":
            return int(parts[2])
    except (ValueError, IndexError):
        pass
    return None

# 🔒 Middleware de Autenticação (aplicado globalmente, exceto para rotas públicas)
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
        "/debug/stripe",
        "/api/nowpayments/check-config",
        "/api/nowpayments/test-webhook",
    ]
    
    # Exclui rotas de admin e OPTIONS
    if request.path.startswith("/api/site/admin") or request.method == "OPTIONS":
        return
        
    # Rotas públicas
    if request.path in public_routes:
        return

    # Rotas protegidas (requerem token)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization token is missing or invalid"}), 401

    token = auth_header.split(" ")[1]
    user_id = get_user_id_from_token(token)

    if not user_id:
        return jsonify({"error": "Invalid authentication token"}), 401
    
    request.user_id = user_id
    
# 👤 ROTA DE REGISTRO
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
            return jsonify({"error": "User already exists"}), 400

        private_key, wallet_address = generate_polygon_wallet()
        hashed_password = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users (email, password, nickname, wallet_address, private_key) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (email, hashed_password, nickname, wallet_address, private_key)
        )
        user_id = cursor.fetchone()['id']

        # Inicializa o saldo
        cursor.execute(
            "INSERT INTO balances (user_id, available) VALUES (%s, %s)",
            (user_id, 0.0)
        )

        conn.commit()

        # Mock token para login instantâneo
        auth_token = f"mock_token_{user_id}_{int(time.time())}"

        return jsonify({
            "success": True,
            "message": "User registered successfully",
            "user": {
                "id": user_id,
                "email": email,
                "nickname": nickname,
                "wallet_address": wallet_address
            },
            "token": auth_token
        }), 201

    except Exception as e:
        conn.rollback()
        print(f"❌ Erro no registro: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 🔑 ROTA DE LOGIN
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

# ⚙️ ROTA DE SETUP INICIAL (PARA USUÁRIOS CRIADOS VIA COMPRA)
@app.route("/first-time-setup", methods=["POST"])
def first_time_setup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nickname = data.get('nickname')

    if not email or not password or not nickname:
        return jsonify({"error": "Email, password, and nickname are required"}), 400

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
            "UPDATE users SET password = %s, nickname = %s, updated_at = CURRENT_TIMESTAMP WHERE email = %s RETURNING id, wallet_address",
            (hashed_password, nickname, email)
        )
        user = cursor.fetchone()

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

# 🔍 ROTA PARA CHECAR SE O USUÁRIO EXISTE
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

# ✅ ROTA DE HEALTH CHECK - PRODUÇÃO (ATUALIZADA)
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Allianza Wallet Backend",
        "version": "1.0.0",
        "environment": "production",
        "stripe_available": STRIPE_AVAILABLE,
        "stripe_environment": "production" if stripe and stripe.api_key and stripe.api_key.startswith('sk_live_') else "test",
        "nowpayments_configured": bool(NOWPAYMENTS_IPN_SECRET),
        "nowpayments_webhook_url": "https://allianza-wallet-backend.onrender.com/webhook/nowpayments",
        "nowpayments_status": "ACTIVE" if NOWPAYMENTS_IPN_SECRET else "INACTIVE"
    } ), 200

# ✅ Rota para informações do sistema - PRODUÇÃO (ATUALIZADA)
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
            "stripe_environment": "production" if stripe and stripe.api_key and stripe.api_key.startswith('sk_live_') else "test",
            "neon_database": True,
            "nowpayments_webhook": True,
            "nowpayments_configured": bool(NOWPAYMENTS_IPN_SECRET)
        },
        "cors_domains": [
            "http://localhost:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "https://allianza.tech",
            "https://admin.allianza.tech", 
            "https://wallet.allianza.tech"
        ]
    } ), 200

# ✅ ENDPOINT DE DIAGNÓSTICO STRIPE - PRODUÇÃO
@app.route('/debug/stripe', methods=['GET'])
def debug_stripe():
    is_production = stripe and stripe.api_key and stripe.api_key.startswith('sk_live_')
    return jsonify({
        'stripe_available': STRIPE_AVAILABLE,
        'stripe_installed': STRIPE_AVAILABLE,
        'stripe_version': "8.0.0",
        'api_key_configured': bool(stripe.api_key) if STRIPE_AVAILABLE else False,
        'environment': 'production' if is_production else 'test',
        'env_key_exists': bool(os.getenv('STRIPE_SECRET_KEY')),
        'status': 'Operational' if STRIPE_AVAILABLE else 'Not Available'
    }), 200

# ✅ ROTAS PARA BALANCES E LEDGER
@app.route('/balances/me', methods=['GET'])
@token_required
def get_balances_me():
    try:
        user_id = request.user_id
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT available, locked, staking_balance FROM balances WHERE user_id = %s AND asset = 'ALZ'", (user_id,))
        balance_data = cursor.fetchone()
        
        balance = {"available_balance": 0.0, "locked_balance": 0.0, "staking_balance": 0.0, "total_balance": 0.0, "asset": "ALZ"}
        
        if balance_data:
            balance["available_balance"] = float(balance_data["available"]) if balance_data["available"] else 0.0
            balance["locked_balance"] = float(balance_data["locked"]) if balance_data["locked"] else 0.0
            balance["staking_balance"] = float(balance_data["staking_balance"]) if balance_data["staking_balance"] else 0.0
            balance["total_balance"] = balance["available_balance"] + balance["staking_balance"]
            
        return jsonify({"balance": balance}), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar saldo: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/ledger/history', methods=['GET'])
@token_required
def get_ledger_history():
    try:
        user_id = request.user_id
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
        
        # Converte o resultado para um formato JSON serializável
        data_list = []
        for entry in entries:
            entry_dict = dict(entry)
            entry_dict['amount'] = float(entry_dict['amount'])
            data_list.append(entry_dict)
            
        return jsonify({"history": data_list}), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar histórico do ledger: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# 🚀 INICIALIZAÇÃO DO FLASK
if __name__ == '__main__':
    print("=" * 60)
    print("🔗 Rotas disponíveis:")
    print("🔗 Rotas públicas:")
    print("   - GET  /health")
    print("   - GET  /system/info")
    print("   - POST /register")
    print("   - POST /login")
    print("   - POST /first-time-setup")
    print("   - POST /check-user")
    print("   - POST /api/site/purchase")
    print("   - POST /create-checkout-session")
    print("   - GET  /debug/stripe")
    print("🔗 NowPayments (PÚBLICAS):")
    print("   - GET  /api/nowpayments/check-config")
    print("   - POST /api/nowpayments/test-webhook")
    print("   - POST /webhook/nowpayments")
    print("🔐 Rotas admin (requer token):")
    print("   - GET  /api/site/admin/payments")
    print("   - GET  /api/site/admin/stats")
    print("   - POST /api/site/admin/process-payments")
    print("   - POST /api/site/admin/manual-token-send")
    print("   - POST /api/site/admin/create-staking-table")
    print("   - GET  /api/site/admin/check-tables")
    print("📞 Webhooks:")
    print("   - POST /webhook/stripe")
    print("   - POST /webhook/nowpayments")
    print("💰 Rotas protegidas:")
    print("   - GET  /balances/me")
    print("   - GET  /ledger/history")
    print("🎯 Staking Routes:")
    print("   - POST /staking/stake")
    print("   - POST /staking/unstake")
    print("   - POST /staking/claim-rewards")
    print("   - GET  /staking/me")
    print("   - GET  /staking/options")
    print("   - GET  /staking/stats")
    print("   - PUT  /staking/auto-compound/<stake_id>")
    print("=" * 60)
    
    try:
        app.run(debug=False, port=5000, host='0.0.0.0')
    except Exception as e:
        print(f"❌ Erro ao iniciar o servidor Flask: {e}")
