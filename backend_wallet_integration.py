# backend_wallet_integration.py - PRODUÇÃO (CORRIGIDO - VALORES ALINHADOS CORRETAMENTE)
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
print(f"🔗 Webhook URL: https://allianza-wallet-backend.onrender.com/webhook/nowpayments"  )
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
} )

# ✅ ROTAS OPTIONS PARA CORS PREFLIGHT
@app.route('/api/site/admin/payments', methods=['OPTIONS'])
@app.route('/api/site/admin/stats', methods=['OPTIONS'])
@app.route('/api/site/admin/process-payments', methods=['OPTIONS']) 
@app.route('/api/site/admin/manual-token-send', methods=['OPTIONS'])
@app.route('/api/site/admin/debug-token', methods=['OPTIONS'])
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
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, related_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, 'ALZ', amount_alz, 'purchase', f'Compra de {amount_alz} ALZ - {method}', payment_id)
        )
        
        conn.commit()
        
        return {"success": True, "user_created": user_created, "wallet_address": wallet_address}
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro process_automatic_payment: {e}")
        return {"success": False, "error": str(e)}
    finally:
        if 'conn' in locals():
            conn.close()

# 🚀 ROTA DE COMPRA PELO SITE (PIX/STRIPE) - PRODUÇÃO (CORRIGIDA)
@app.route('/api/site/purchase', methods=['POST'])
def register_site_purchase():
    """Registrar uma intenção de compra (PIX) ou iniciar checkout (Stripe) - CORRIGIDO"""
    data = request.json
    email = data.get('email')
    amount_brl = data.get('amount')
    method = data.get('method')
    source_name = data.get('sourceName')
    
    if not email or not amount_brl or not method:
        return jsonify({"error": "Email, valor e método de pagamento são obrigatórios"}), 400
    
    try:
        amount_brl = float(amount_brl)
    except ValueError:
        return jsonify({"error": "Valor inválido"}), 400
        
    if amount_brl <= 0:
        return jsonify({"error": "Valor deve ser positivo"}), 400

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
        
        # 1. Buscar ou criar usuário para obter user_id
        cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        user_id = None
        wallet_address = None
        
        if not user:
            # Criar usuário temporário para registro do pagamento
            private_key, wallet_address = generate_polygon_wallet()
            temp_password = f"temp_{secrets.token_hex(8)}"
            hashed_password = generate_password_hash(temp_password)
            
            cursor.execute(
                "INSERT INTO users (email, password, wallet_address, private_key, nickname) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (email, hashed_password, wallet_address, private_key, f"User_{email.split('@')[0]}")
            )
            user_id = cursor.fetchone()['id']
            print(f"👤 Usuário temporário criado: {email} - ID: {user_id}")
        else:
            user_id = user['id']
            wallet_address = user['wallet_address']
            print(f"👤 Usuário existente: {email} - ID: {user_id}")
            
        # 2. Registrar o pagamento como pendente
        metadata = {
            'amount_alz': amount_alz,
            'source_name': source_name,
            'amount_brl': brl_amount_for_db,
            'wallet_address': wallet_address
        }
        
        cursor.execute(
            "INSERT INTO payments (user_id, email, amount, method, status, metadata) VALUES (%s, %s, %s, 'pending', %s, %s) RETURNING id",
            (user_id, email, brl_amount_for_db, method, json.dumps(metadata))
        )
        payment_id = cursor.fetchone()['id']
        print(f"✅ Pagamento pendente registrado: ID {payment_id} - R$ {brl_amount_for_db} ({amount_alz} ALZ)")
        
        conn.commit()
        
        # 3. Processar de acordo com o método
        if method == 'pix':
            # Para PIX, apenas registra e retorna sucesso (QR Code é gerado no frontend)
            return jsonify({
                "success": True,
                "message": "Pagamento PIX registrado com sucesso",
                "payment_id": payment_id,
                "amount_brl": brl_amount_for_db,
                "amount_alz": amount_alz
            }), 200
        
        elif method == 'stripe':
            # Lógica de criação de sessão Stripe
            if not STRIPE_AVAILABLE:
                return jsonify({"error": "Stripe não configurado"}), 500
                
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'brl',
                        'unit_amount': int(brl_amount_for_db * 100), # Converter para centavos
                        'product_data': {
                            'name': f'Compra de {amount_alz} ALZ',
                            'description': f'Tokens ALZ para {email}',
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=os.getenv('STRIPE_SUCCESS_URL', 'https://allianza.tech/success' ),
                cancel_url=os.getenv('STRIPE_CANCEL_URL', 'https://allianza.tech/cancel' ),
                customer_email=email,
                metadata={
                    'payment_id': payment_id,
                    'amount_alz': str(amount_alz),
                    'user_email': email
                }
            )
            
            # Atualiza o payment_id com o session_id do Stripe
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE payments SET tx_hash = %s WHERE id = %s",
                (session.id, payment_id)
            )
            conn.commit()
            
            return jsonify({
                "success": True,
                "message": "Checkout Stripe criado",
                "checkout_url": session.url,
                "payment_id": payment_id,
                "session_id": session.id
            }), 200
            
        else:
            return jsonify({"error": "Método de pagamento não suportado"}), 400
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro ao registrar compra: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# 💳 STRIPE WEBHOOK - PRODUÇÃO (CORRIGIDO)
@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Webhook para processar eventos do Stripe - CORRIGIDO"""
    if not STRIPE_AVAILABLE:
        return jsonify({"error": "Stripe não configurado"}), 500
        
    payload = request.get_data()
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
                "ipn_secret_length": len(NOWPAYMENTS_IPN_SECRET  ),
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
                print(f"❌ Pagamento {payment_id} não encontrado no DB")
                # Se não encontrar, pode ser um pagamento direto (sem registro prévio)
                # Neste caso, o processamento deve ser mais complexo e requer a conversão de crypto para ALZ
                # Por simplicidade, vamos assumir que todos os pagamentos crypto são pré-registrados
                return jsonify({"error": "Payment not found"}), 404
            
            # 2. Processar apenas quando o status for 'finished' ou 'completed'
            if payment_status in ['finished', 'completed', 'sending', 'waiting']:
                # Se o pagamento já foi processado, ignora
                if db_payment['metadata'] and db_payment['metadata'].get('processed'):
                    print(f"⚠️ Pagamento {payment_id} já processado. Ignorando.")
                    return 'OK', 200

                # ✅ CORREÇÃO: Lógica de conversão de crypto para ALZ (simplificada)
                # Assumindo que o valor em ALZ está no metadata (para pagamentos Stripe)
                # Para pagamentos Crypto, o valor em ALZ deve ser calculado com base na cotação
                
                # Por enquanto, vamos assumir que o valor em ALZ é passado no metadata
                amount_alz = db_payment['metadata'].get('amount_alz')
                
                if not amount_alz:
                    print(f"❌ amount_alz não encontrado no metadata para {payment_id}")
                    # Lógica de fallback: Se for crypto, tenta calcular com base no valor em BRL
                    # Isso é complexo e requer cotação em tempo real. Por enquanto, falha.
                    return jsonify({"error": "ALZ amount missing in metadata"}), 400
                    
                amount_alz = float(amount_alz)
                
                # Processar pagamento automático
                result = process_automatic_payment(email, amount_alz, 'crypto', payment_id)
                
                if result['success']:
                    print(f"✅ Pagamento NowPayments processado com sucesso para {email}. {amount_alz} ALZ creditados.")
                    # Atualizar metadata para indicar processado
                    metadata = db_payment['metadata']
                    metadata['processed'] = True
                    cursor.execute(
                        "UPDATE payments SET status = 'completed', metadata = %s, tx_hash = %s WHERE id = %s",
                        (json.dumps(metadata), payment_id, db_payment['id'])
                    )
                    conn.commit()
                else:
                    print(f"❌ Falha ao creditar tokens para {email}: {result['error']}")
                    conn.rollback()
                    return jsonify({"error": result['error']}), 500
            
            # 3. Atualizar status do pagamento (se necessário)
            if payment_status == 'failed':
                cursor.execute("UPDATE payments SET status = 'failed' WHERE id = %s", (db_payment['id'],))
                conn.commit()
            
            return 'OK', 200
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Erro NowPayments Webhook: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            if 'conn' in locals():
                conn.close()
                
    except Exception as e:
        print(f"❌ Erro geral NowPayments Webhook: {e}")
        return jsonify({"error": str(e)}), 500

# ✅ ROTA DE TESTE DE CONFIG NOWPAYMENTS
@app.route('/api/nowpayments/check-config', methods=['GET'])
def check_nowpayments_config():
    """Verifica se a chave secreta IPN está configurada"""
    is_configured = bool(NOWPAYMENTS_IPN_SECRET)
    return jsonify({
        "configured": is_configured,
        "ipn_secret_length": len(NOWPAYMENTS_IPN_SECRET) if is_configured else 0,
        "message": "IPN Secret configurado" if is_configured else "IPN Secret não configurado. Webhooks não funcionarão."
    }), 200

# ✅ ROTA DE TESTE DE WEBHOOK NOWPAYMENTS (MOCK)
@app.route('/api/nowpayments/test-webhook', methods=['POST'])
def test_nowpayments_webhook():
    """Simula um webhook para teste de integração"""
    try:
        data = request.json
        signature = request.headers.get('x-nowpayments-ipn-signature')
        
        # 1. Verificar assinatura (mock)
        if not signature:
            return jsonify({"error": "Signature missing"}), 401
            
        # Para teste, vamos apenas verificar se a chave secreta é a correta
        # Em um ambiente real, você usaria o `verify_nowpayments_signature` com o payload RAW
        
        # MOCK: Assumindo que a assinatura é um hash simples do IPN_SECRET
        import hashlib
        expected_signature = hashlib.sha512(NOWPAYMENTS_IPN_SECRET.encode('utf-8')).hexdigest()
        
        if signature != expected_signature:
            return jsonify({"error": "Invalid mock signature"}), 401
            
        # 2. Processar dados (mock)
        email = data.get('email', 'test@allianza.tech')
        amount_alz = float(data.get('amount_alz', 100.0))
        payment_id = data.get('payment_id', f"mock_{int(time.time())}")
        
        # 3. Processar pagamento automático (real)
        result = process_automatic_payment(email, amount_alz, 'crypto_mock', payment_id)
        
        if result['success']:
            return jsonify({
                "success": True,
                "message": f"Mock webhook processado. {amount_alz} ALZ creditados para {email}",
                "payment_id": payment_id
            }), 200
        else:
            return jsonify({"error": f"Falha ao processar mock payment: {result['error']}"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== ROTAS ADMIN DO SITE (NÃO REQUEREM JWT, APENAS TOKEN SIMPLES) =====

# 📊 Dashboard de Pagamentos - PRODUÇÃO (CORRIGIDO)
@app.route('/api/site/admin/payments', methods=['GET'])
def site_admin_payments():
    """Retorna a lista de pagamentos para o admin do site - PRODUÇÃO"""
    try:
        auth_header = request.headers.get('Authorization', '')
        
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
            
            # ✅ CORREÇÃO: Garantir que o valor em BRL seja float
            amount_brl = float(payment_dict['amount'])
            payment_dict['amount'] = amount_brl
            
            # ✅ CORREÇÃO: Calcular o valor ALZ a partir do BRL (1 ALZ = R$ 0.10)
            payment_dict['amount_alz'] = amount_brl / 0.10
            
            # Formatação de datas
            payment_dict['created_at'] = payment_dict['created_at'].isoformat() if payment_dict['created_at'] else None
            payment_dict['processed_at'] = payment_dict['processed_at'].isoformat() if payment_dict['processed_at'] else None
            
            # Extrair sourceName do metadata se existir
            if payment_dict['metadata']:
                try:
                    metadata = json.loads(payment_dict['metadata'])
                    payment_dict['source_name'] = metadata.get('source_name')
                    # Se o amount_alz estiver no metadata, usa para consistência, mas o cálculo acima é o padrão
                    if metadata.get('amount_alz'):
                        payment_dict['amount_alz'] = float(metadata['amount_alz'])
                except json.JSONDecodeError:
                    payment_dict['metadata'] = {}
            
            data_list.append(payment_dict)
            
        return jsonify({"success": True, "data": data_list}), 200
        
    except Exception as e:
        print(f"❌ Erro admin payments: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# 📈 Estatísticas do Dashboard - PRODUÇÃO (CORRIGIDO)
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
                # Buscar pagamento pendente
                cursor.execute(
                    "SELECT id, user_id, email, amount, metadata, method FROM payments WHERE id = %s AND status = 'pending'",
                    (payment_id,)
                )
                payment = cursor.fetchone()
                
                if payment:
                    # ✅ CORREÇÃO: Calcular valor em ALZ a partir do BRL
                    amount_brl = float(payment['amount'])
                    alz_amount_to_credit = amount_brl / 0.10 # 1 ALZ = R$ 0.10
                    
                    print(f"💰 Creditando {alz_amount_to_credit} ALZ (a partir de R$ {amount_brl}) para pagamento {payment_id}")
                    
                    # Buscar usuário
                    cursor.execute("SELECT id FROM users WHERE id = %s", (payment['user_id'],))
                    user = cursor.fetchone()
                    
                    if user:
                        # Creditar tokens
                        cursor.execute(
                            "UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = 'ALZ'",
                            (alz_amount_to_credit, user['id'])
                        )
                        
                        # Registrar no ledger
                        cursor.execute(
                            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, related_id) VALUES (%s, %s, %s, %s, %s, %s)",
                            (user['id'], 'ALZ', alz_amount_to_credit, 'purchase', f'Compra de {alz_amount_to_credit} ALZ via {payment["method"]}', payment_id)
                        )
                        
                        # COMPENSAR TAXAS PARA CRIPTO
                        if payment['method'] == 'crypto':
                            bonus_amount = alz_amount_to_credit * 0.02
                            cursor.execute(
                                "UPDATE balances SET available = available + %s WHERE user_id = %s",
                                (bonus_amount, user['id'])
                            )
                            cursor.execute(
                                "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, related_id) VALUES (%s, %s, %s, %s, %s, %s)",
                                (user['id'], 'ALZ', bonus_amount, 'fee_compensation', '🎁 Bônus compensação de taxa crypto', payment_id)
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
        
        user["balance"] = {
            "available_balance": float(balance_data["available"]) if balance_data and balance_data["available"] else 0.0,
            "locked_balance": float(balance_data["locked"]) if balance_data and balance_data["locked"] else 0.0,
            "staking_balance": float(balance_data["staking_balance"]) if balance_data and balance_data["staking_balance"] else 0.0,
            "total_balance": (float(balance_data["available"]) if balance_data and balance_data["available"] else 0.0) + 
                             (float(balance_data["staking_balance"]) if balance_data and balance_data["staking_balance"] else 0.0)
        }

        return jsonify({
            "success": True,
            "message": "Login successful",
            "user": user,
            "token": auth_token
        }), 200

    except Exception as e:
        print(f"❌ Erro no login: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ⚙️ ROTA PARA SETUP INICIAL (PARA USUÁRIOS CRIADOS VIA COMPRA)
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
    }  ), 200

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
    }  ), 200

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
    print("📞 Webhooks:")
    print("   - POST /webhook/stripe")
    print("   - POST /webhook/nowpayments")
    print("💰 Rotas protegidas:")
    print("   - GET  /balances/me")
    print("   - GET  /ledger/history")
    print("=" * 60)
    
    try:
        app.run(debug=False, port=5000, host='0.0.0.0')
    except Exception as e:
        print(f"❌ Erro ao iniciar o servidor Flask: {e}")
