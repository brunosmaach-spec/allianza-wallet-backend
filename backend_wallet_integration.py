# backend_wallet_integration.py - PRODUÇÃO (ATUALIZADO)
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

# ✅ CARREGAR VARIÁVEIS DE AMBIENTE PRIMEIRO
from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("🚀 ALLIANZA WALLET BACKEND - PRODUÇÃO")
print("✅ NOWPAYMENTS CORRIGIDO - WEBHOOK URL COMPLETA")
print("=" * 60)
print(f"🔑 SITE_ADMIN_TOKEN: {os.getenv('SITE_ADMIN_TOKEN', 'NÃO ENCONTRADO')}")
print(f"💳 STRIPE_SECRET_KEY: {'✅ PRODUÇÃO' if os.getenv('STRIPE_SECRET_KEY', '').startswith('sk_live_') else '❌ NÃO ENCONTRADO'}")
print(f"🔗 NOWPAYMENTS_IPN: {'✅ CONFIGURADO' if os.getenv('NOWPAYMENTS_IPN_SECRET') else '❌ NÃO ENCONTRADO'}")
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

# ✅ MIDDLEWARE CORS MANUAL PARA GARANTIR
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '')
    allowed_origins = [
        "https://allianza.tech",
        "https://www.allianza.tech",
        "https://wallet.allianza.tech", 
        "https://www.wallet.allianza.tech",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174"
    ]
    
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,Accept,Origin,Access-Control-Request-Method,Access-Control-Request-Headers')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH,HEAD')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Max-Age', '3600')
    
    return response

# ✅ ROTAS OPTIONS PARA CORS PREFLIGHT
@app.route('/api/site/admin/payments', methods=['OPTIONS'])
@app.route('/api/site/admin/stats', methods=['OPTIONS'])
@app.route('/api/site/admin/process-payments', methods=['OPTIONS']) 
@app.route('/api/site/admin/manual-token-send', methods=['OPTIONS'])
@app.route('/api/site/admin/debug-token', methods=['OPTIONS'])
@app.route('/api/site/purchase', methods=['OPTIONS'])
@app.route('/create-checkout-session', methods=['OPTIONS'])
@app.route('/webhook/nowpayments', methods=['OPTIONS'])  # ✅ NOVO: NowPayments CORS
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
NOWPAYMENTS_IPN_SECRET = os.getenv('NOWPAYMENTS_IPN_SECRET', 'rB4Ic28l8posIjXA4fx90GuGnHagAxEj')

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

# 🔄 FUNÇÃO PARA PROCESSAR PAGAMENTOS AUTOMATICAMENTE (ATUALIZADA COM COMPENSAÇÃO)
def process_automatic_payment(email, amount, method, external_id):
    """Processar pagamento automaticamente e creditar tokens COM COMPENSAÇÃO DE TAXAS"""
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
        
        # Creditar tokens (VALOR COMPLETO)
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
        
        # ✅ COMPENSAR TAXAS PARA CRIPTO (PROMOÇÃO GRATUITA)
        if method == 'crypto':
            compensation_amount = amount * 0.02  # Compensar 2% de taxas
            cursor.execute(
                "UPDATE balances SET available = available + %s WHERE user_id = %s",
                (compensation_amount, user_id)
            )
            cursor.execute(
                "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                (user_id, 'ALZ', compensation_amount, 'fee_compensation', '🎁 Bônus compensação de taxas - Promoção Gratuita')
            )
            print(f"🎁 Bônus de taxas: +{compensation_amount} ALZ para {email}")
        
        # Atualizar pagamento
        cursor.execute(
            "UPDATE payments SET status = 'completed', user_id = %s, processed_at = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id, payment_id)
        )
        
        conn.commit()
        print(f"🎉 Pagamento automático processado com sucesso: {email} - {amount} ALZ + bônus")
        
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

# 🔄 FUNÇÃO PARA COMPENSAR TAXAS MANUALMENTE
def compensate_fees_manually(email, original_amount, received_amount):
    """Compensar taxas manualmente para garantir valor completo"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar usuário
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user and original_amount > received_amount:
            # Calcular diferença
            difference = original_amount - received_amount
            
            # Creditar a diferença
            cursor.execute(
                "UPDATE balances SET available = available + %s WHERE user_id = %s",
                (difference, user['id'])
            )
            
            # Registrar no ledger
            cursor.execute(
                "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                (user['id'], 'ALZ', difference, 'fee_compensation', '🎁 Compensação manual de taxas - Valor Completo')
            )
            
            conn.commit()
            print(f"✅ Taxas compensadas manualmente para {email}: +{difference} ALZ")
            return difference
        
    except Exception as e:
        print(f"❌ Erro ao compensar taxas manualmente: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
    return 0

# ✅ ROTA DE DEBUG PARA VERIFICAR TOKEN
@app.route('/api/site/admin/debug-token', methods=['GET', 'POST'])
def debug_token():
    """Debug completo para verificar o token"""
    auth_header = request.headers.get('Authorization', '')
    
    print("=" * 60)
    print("🔐 DEBUG TOKEN - INÍCIO")
    print(f"📨 Método: {request.method}")
    print(f"📨 Header Authorization: {auth_header}")
    print(f"🌐 Origin: {request.headers.get('Origin')}")
    print(f"🌐 Host: {request.headers.get('Host')}")
    
    if not auth_header.startswith('Bearer '):
        print("❌ Header não começa com Bearer")
        return jsonify({
            "error": "Header não começa com Bearer",
            "header_received": auth_header
        }), 401
    
    admin_token = auth_header.replace('Bearer ', '').strip()
    expected_token = SITE_ADMIN_TOKEN
    
    print(f"🔑 Token recebido: '{admin_token}'")
    print(f"🔑 Token esperado: '{expected_token}'")
    print(f"📏 Comprimento recebido: {len(admin_token)}")
    print(f"📏 Comprimento esperado: {len(expected_token)}")
    print(f"✅ Tokens são iguais? {admin_token == expected_token}")
    
    # Verificação caractere por caractere
    if admin_token != expected_token:
        print("❌ Tokens não coincidem!")
        print("🔍 Comparação caractere por caractere:")
        max_len = max(len(admin_token), len(expected_token))
        for i in range(max_len):
            char_rec = admin_token[i] if i < len(admin_token) else '❌ FIM'
            char_exp = expected_token[i] if i < len(expected_token) else '❌ FIM'
            match = "✅" if char_rec == char_exp else "❌"
            print(f"   Posição {i}: '{char_rec}' {match} '{char_exp}'")
    
    print("🔐 DEBUG TOKEN - FIM")
    print("=" * 60)
    
    if admin_token == expected_token:
        return jsonify({
            "success": True,
            "message": "Token válido!",
            "token_length": len(admin_token),
            "token_match": True,
            "backend_token_preview": f"{expected_token[:10]}...{expected_token[-4:]}"
        }), 200
    else:
        return jsonify({
            "error": "Token inválido",
            "token_received": admin_token,
            "token_expected": expected_token,
            "token_length_received": len(admin_token),
            "token_length_expected": len(expected_token),
            "token_match": False
        }), 401

# 🔄 ROTA PARA ENVIO MANUAL DE TOKENS (ADMIN) - PRODUÇÃO
@app.route('/api/site/admin/manual-token-send', methods=['POST'])
def site_admin_manual_token_send():
    """Enviar tokens manualmente para qualquer email - PRODUÇÃO"""
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
                # Se o usuário não existe, criar um registro pendente
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

# 💳 ROTA PARA CRIAR SESSÃO STRIPE - PRODUÇÃO
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """Criar sessão de checkout Stripe - PRODUÇÃO"""
    
    if not STRIPE_AVAILABLE:
        return jsonify({
            'error': 'Stripe não disponível no servidor',
            'stripe_available': False
        }), 503
        
    try:
        data = request.json
        amount = data.get('amount')
        email = data.get('email')
        currency = data.get('currency', 'brl')
        
        if not amount or not email:
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
        
        # URLs para produção
        success_url = 'https://allianza.tech/success'
        cancel_url = 'https://allianza.tech/cancel'
        
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
                success_url=success_url,
                cancel_url=cancel_url,
                customer_email=email,
                metadata={
                    'email': email, 
                    'amount_brl': amount_int / 100,
                    'source': 'allianza_site_production'
                }
            )
            
            return jsonify({
                'id': session.id,
                'url': session.url,
                'success': True,
                'message': 'Sessão de pagamento criada com sucesso'
            })
            
        except stripe.error.StripeError as stripe_error:
            return jsonify({
                'error': f'Erro do Stripe: {str(stripe_error)}'
            }), 400
            
    except Exception as e:
        return jsonify({
            'error': f'Erro interno do servidor: {str(e)}'
        }), 500

# 🌐 WEBHOOKS PARA PAGAMENTOS AUTOMÁTICOS - PRODUÇÃO
@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Webhook para pagamentos Stripe (Cartão) - PRODUÇÃO"""
    if not STRIPE_AVAILABLE:
        return jsonify({'error': 'Stripe não disponível'}), 503
        
    try:
        payload = request.get_data()
        sig_header = request.headers.get('Stripe-Signature')
        
        print(f"📥 Webhook Stripe PRODUÇÃO recebido: {request.headers}")
        
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
        
        print(f"📊 Evento Stripe PRODUÇÃO: {event['type']}")
        
        if event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']
            email = payment_intent.get('receipt_email') or payment_intent['metadata'].get('email')
            amount = payment_intent['amount'] / 100
            payment_id = payment_intent['id']
            
            if email and amount > 0:
                result = process_automatic_payment(email, amount, 'credit_card', payment_id)
                return jsonify(result), 200
            else:
                print("⚠️ Email ou valor inválido no webhook Stripe PRODUÇÃO")
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
        print(f"❌ Erro webhook Stripe PRODUÇÃO: {e}")
        return jsonify({'error': str(e)}), 400

# ✅ FUNÇÃO PARA VERIFICAR ASSINATURA NOWPAYMENTS (CORRIGIDA)
def verify_nowpayments_signature(payload_bytes, received_signature):
    """Verificar assinatura NowPayments CORRETAMENTE"""
    try:
        if not received_signature:
            print("❌ Assinatura não fornecida")
            return False
            
        # ✅ CORREÇÃO: Usar bytes do payload diretamente
        expected_signature = hmac.new(
            key=NOWPAYMENTS_IPN_SECRET.encode('utf-8'),
            msg=payload_bytes,  # Já em bytes
            digestmod=hashlib.sha512
        ).hexdigest()
        
        print(f"🔐 Assinatura esperada: {expected_signature}")
        print(f"🔐 Assinatura recebida: {received_signature}")
        
        return hmac.compare_digest(received_signature, expected_signature)
        
    except Exception as e:
        print(f"❌ Erro verificação assinatura: {e}")
        return False

# ✅ FUNÇÃO PARA EXTRAIR DADOS NOWPAYMENTS (CORRIGIDA)
def extract_nowpayments_data(data):
    """Extrai dados CORRETAMENTE do payload NowPayments"""
    try:
        print(f"📦 Payload completo recebido: {data}")
        
        # ✅ CORREÇÃO: Campos conforme documentação oficial
        payment_status = data.get('payment_status')
        payment_id = data.get('payment_id')
        
        # Múltiplos campos possíveis para email
        email = (data.get('customer_email') or 
                data.get('payer_email') or
                data.get('buyer_email') or
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
    """Webhook NowPayments - URL CORRETA: /webhook/nowpayments"""
    try:
        print("=" * 70)
        print("🎯 NOWPAYMENTS WEBHOOK CHAMADO - URL CORRETA")
        print("=" * 70)
        
        # Se for GET, retorna status (para teste)
        if request.method == 'GET':
            return jsonify({
                "status": "active", 
                "message": "NowPayments webhook está operacional",
                "webhook_url": "https://allianza-wallet-backend.onrender.com/webhook/nowpayments",
                "method": "POST",
                "ipn_secret_length": len(NOWPAYMENTS_IPN_SECRET),
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
        amount = payment_data['amount']
        payment_id = payment_data['payment_id']
        
        print(f"📊 Status do pagamento: {payment_status}")
        print(f"📧 Email identificado: {email}")
        print(f"💰 Valor: {amount}")
        print(f"🆔 ID do pagamento: {payment_id}")
        
        # ✅ CORREÇÃO: Lógica de status aprimorada
        if payment_status in ['finished', 'confirmed', 'success']:
            if not email:
                print("❌ Email não encontrado no payload")
                return jsonify({'error': 'Email not found in payload'}), 400
            
            if amount <= 0:
                print("❌ Valor inválido")
                return jsonify({'error': 'Invalid amount'}), 400
            
            print(f"🎯 Processando pagamento confirmado: {email} - {amount}")
            
            try:
                # Processar pagamento automático
                result = process_automatic_payment(email, amount, 'crypto', payment_id)
                print(f"✅ Pagamento processado com sucesso: {result}")
                return jsonify(result), 200
                
            except Exception as e:
                print(f"❌ Erro processamento pagamento: {e}")
                return jsonify({'error': f'Payment processing failed: {str(e)}'}), 500
                
        elif payment_status == 'failed':
            print(f"❌ Pagamento falhou: {payment_id}")
            log_payment_failure(payment_id, data, 'failed')
            return jsonify({'success': True, 'message': 'Payment failure logged'}), 200
            
        elif payment_status in ['waiting', 'confirming', 'partially_paid']:
            print(f"⏳ Status intermediário: {payment_status}")
            return jsonify({'success': True, 'message': f'Waiting for confirmation: {payment_status}'}), 200
            
        else:
            print(f"⚠️ Status desconhecido: {payment_status}")
            return jsonify({'success': True, 'message': f'Unknown status: {payment_status}'}), 200
            
    except Exception as e:
        print(f"❌ ERRO CRÍTICO no webhook: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Webhook processing failed: {str(e)}'}), 500

def log_payment_failure(payment_id, data, status):
    """Registrar falha de pagamento"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        email = data.get('customer_email') or data.get('payer_email')
        amount = data.get('pay_amount', 0)
        
        cursor.execute('''
            INSERT INTO payment_logs 
            (payment_id, email, amount, status, raw_data, created_at)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ''', (payment_id, email, amount, status, json.dumps(data)))
        
        conn.commit()
        conn.close()
        print(f"📝 Falha registrada no banco: {payment_id}")
    except Exception as e:
        print(f"❌ Erro ao registrar falha: {e}")

# ✅ ENDPOINT DE DIAGNÓSTICO NOWPAYMENTS
@app.route('/api/nowpayments/diagnostic', methods=['GET'])
def nowpayments_diagnostic():
    """Diagnóstico completo da NowPayments"""
    return jsonify({
        'nowpayments_configured': bool(NOWPAYMENTS_IPN_SECRET),
        'ipn_secret_length': len(NOWPAYMENTS_IPN_SECRET),
        'required_secret_length': 64,
        'webhook_url': 'https://allianza-wallet-backend.onrender.com/webhook/nowpayments',
        'status': 'OPERATIONAL' if len(NOWPAYMENTS_IPN_SECRET) >= 32 else 'CONFIGURATION_ERROR',
        'fix_required': len(NOWPAYMENTS_IPN_SECRET) < 32,
        'setup_instructions': {
            'webhook_url': 'https://allianza-wallet-backend.onrender.com/webhook/nowpayments',
            'ipn_secret': NOWPAYMENTS_IPN_SECRET,
            'note': 'Configure no painel NowPayments em Payment flow customization -> Instant payment notifications'
        }
    })

# ✅ TESTE DE ASSINATURA NOWPAYMENTS
@app.route('/api/nowpayments/test-signature', methods=['GET', 'POST'])
def test_nowpayments_signature():
    """Testar geração de assinatura"""
    test_data = {
        "payment_id": "test_123456789",
        "payment_status": "finished", 
        "pay_amount": 100.0,
        "actually_paid": 100.0,
        "pay_currency": "usdt",
        "customer_email": "test@allianza.tech"
    }
    
    payload_bytes = json.dumps(test_data).encode('utf-8')
    signature = hmac.new(
        key=NOWPAYMENTS_IPN_SECRET.encode('utf-8'),
        msg=payload_bytes,
        digestmod=hashlib.sha512
    ).hexdigest()
    
    return jsonify({
        'test_payload': test_data,
        'generated_signature': signature,
        'ipn_secret_preview': NOWPAYMENTS_IPN_SECRET[:8] + '...' + NOWPAYMENTS_IPN_SECRET[-8:],
        'signature_length': len(signature),
        'verification_url': '/webhook/nowpayments',
        'headers_required': {
            'Content-Type': 'application/json',
            'x-nowpayments-ipn-signature': signature
        },
        'curl_test_command': f'curl -X POST https://allianza-wallet-backend.onrender.com/webhook/nowpayments -H "Content-Type: application/json" -H "x-nowpayments-ipn-signature: {signature}" -d \'{json.dumps(test_data)}\''
    })

# 🔑 Login Admin - PRODUÇÃO
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

# 🔄 Rota para o Site processar pagamentos - PRODUÇÃO
@app.route('/api/site/purchase', methods=['POST'])
def site_process_purchase():
    """Processar compra do site - PRODUÇÃO"""
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

# 🔄 Rota para Admin do Site - PRODUÇÃO (COM DEBUG)
@app.route('/api/site/admin/payments', methods=['GET'])
def site_admin_payments():
    """Listar pagamentos para o admin do site - PRODUÇÃO"""
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
                   p.processed_at, u.wallet_address, u.nickname
            FROM payments p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        ''')
        payments = cursor.fetchall()
        
        print(f"✅ Retornando {len(payments)} pagamentos")
        
        return jsonify({
            "success": True,
            "data": [dict(payment) for payment in payments]
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

# 🔄 Processar Pagamentos PIX Manualmente (Admin) - PRODUÇÃO
@app.route('/api/site/admin/process-payments', methods=['POST'])
def site_admin_process_payments():
    """Processar pagamentos PIX manualmente - PRODUÇÃO"""
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
                    # Creditar valor completo
                    cursor.execute(
                        "UPDATE balances SET available = available + %s WHERE user_id = %s",
                        (payment['amount'], payment['user_id'])
                    )
                    
                    # ✅ COMPENSAR TAXAS PARA CRIPTO
                    if payment['method'] == 'crypto':
                        bonus_amount = float(payment['amount']) * 0.02  # Bônus de 2%
                        cursor.execute(
                            "UPDATE balances SET available = available + %s WHERE user_id = %s",
                            (bonus_amount, payment['user_id'])
                        )
                        cursor.execute(
                            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                            (payment['user_id'], 'ALZ', bonus_amount, 'fee_compensation', '🎁 Bônus promoção gratuita')
                        )
                        print(f"🎁 Bônus aplicado para {payment['email']}: +{bonus_amount} ALZ")
                    
                    cursor.execute(
                        "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
                        (payment['user_id'], 'ALZ', payment['amount'], 'purchase', f'Compra PIX processada - Payment ID: {payment_id}')
                    )
                    
                    cursor.execute(
                        "UPDATE payments SET status = 'completed', processed_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (payment_id,)
                    )
                    
                    processed_count += 1
                    print(f"✅ Tokens creditados para pagamento {payment_id}: {payment['amount']} ALZ + bônus")
            
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

# ₿ Rota para criar fatura NowPayments (API)
@app.route('/api/nowpayments/create-invoice', methods=['POST'])
def create_nowpayments_invoice():
    if not NOWPAYMENTS_API_KEY:
        return jsonify({"error": "NowPayments API Key não configurada no backend"}), 500

    data = request.get_json()
    amount = data.get('amount')
    email = data.get('email')
    
    if not amount or not email:
        return jsonify({"error": "Parâmetros 'amount' e 'email' são obrigatórios"}), 400

    try:
        # ✅ 1. REGISTRAR PAGAMENTO NO BANCO (STATUS: PENDING_NOWPAYMENTS)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Taxa de conversão R$ para ALZ (1 ALZ = R$ 0,10)
        alz_amount = float(amount) / 0.10
        
        cursor.execute("BEGIN")
        
        # Buscar ou criar usuário (lógica simplificada para fins de teste)
        cursor.execute("SELECT id, wallet_address FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        user_id = None
        if user:
            user_id = user['id']

        # Registrar pagamento com status pendente e valor em ALZ
        cursor.execute(
            "INSERT INTO payments (email, amount, method, status, user_id) VALUES (%s, %s, %s, 'pending_nowpayments', %s) RETURNING id",
            (email, alz_amount, 'crypto', user_id)
        )
        payment_id = cursor.fetchone()['id']
        
        # ✅ 2. CRIAR FATURA NA NOWPAYMENTS
        nowpayments_url = "https://api.nowpayments.io/v1/invoice"
        headers = {
            "x-api-key": NOWPAYMENTS_API_KEY,
            "Content-Type": "application/json"
        }
        payload = {
            "price_amount": float(amount),
            "price_currency": "brl",
            "pay_currency": "usdt",
            "ipn_callback_url": f"https://allianza-wallet-backend.onrender.com/webhook/nowpayments", # ✅ URL DO SEU BACKEND
            "order_id": str(payment_id), # ✅ USAR O ID DO PAGAMENTO DO SEU BANCO
            "order_description": f"Compra de {alz_amount:.2f} ALZ por R$ {float(amount):.2f}",
            "success_url": "https://allianza.tech/success",
            "cancel_url": "https://allianza.tech/cancel",
            "buyer_email": email
        }
        
        response = requests.post(nowpayments_url, headers=headers, json=payload)
        response.raise_for_status()
        invoice_data = response.json()
        
        # ✅ 3. ATUALIZAR PAGAMENTO COM ID DA FATURA
        cursor.execute(
            "UPDATE payments SET external_id = %s WHERE id = %s",
            (invoice_data.get('id'), payment_id)
        )
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": "Fatura NowPayments criada com sucesso",
            "invoice_url": invoice_data.get('invoice_url'),
            "payment_id": payment_id,
            "invoice_id": invoice_data.get('id')
        }), 200
        
    except requests.exceptions.RequestException as req_e:
        conn.rollback()
        print(f"❌ Erro na API NowPayments: {req_e.response.text if req_e.response else str(req_e)}")
        return jsonify({"error": f"Erro ao criar fatura NowPayments: {req_e.response.text if req_e.response else str(req_e)}"}), 500
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro geral create-invoice: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# 🔄 Rota para Admin do Site - PRODUÇÃO (COM DEBUG)
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
        "/debug/stripe",
        "/api/site/admin/debug-token",
        "/api/nowpayments/diagnostic",  # ✅ NOVO
        "/api/nowpayments/test-signature"  # ✅ NOVO
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
    }), 200

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
            "https://wallet.allianza.tech"
        ]
    }), 200

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
    print("🚀 INICIANDO SERVIDOR ALLIANZA WALLET BACKEND - PRODUÇÃO")
    print("=" * 60)
    print(f"🔑 Token Admin Site: {SITE_ADMIN_TOKEN}")
    print(f"🔐 Stripe Disponível: {STRIPE_AVAILABLE}")
    print(f"🔗 NowPayments Webhook: https://allianza-wallet-backend.onrender.com/webhook/nowpayments")
    print(f"🔑 NowPayments IPN Secret: {NOWPAYMENTS_IPN_SECRET[:8]}... ({len(NOWPAYMENTS_IPN_SECRET)} chars)")
    
    if STRIPE_AVAILABLE:
        is_production = stripe.api_key.startswith('sk_live_')
        print(f"📦 Versão Stripe: 8.0.0")
        print(f"🌐 Ambiente Stripe: {'PRODUÇÃO 🎉' if is_production else 'TESTE ⚠️'}")
    
    print("🎁 SISTEMA CONFIGURADO COM TRANSFERÊNCIAS GRATUITAS")
    print("💸 Compensação automática de 2% para pagamentos cripto")
    print("🌐 Rotas públicas:")
    print("   - GET  /health")
    print("   - GET  /system/info") 
    print("   - POST /api/site/purchase")
    print("   - POST /register, /login, /first-time-setup, /check-user")
    print("   - POST /create-checkout-session")
    print("   - GET  /debug/stripe")
    print("   - POST /api/site/admin/manual-token-send")
    print("   - GET  /api/site/admin/debug-token")
    print("🔗 NowPayments:")
    print("   - POST /webhook/nowpayments")
    print("   - GET  /api/nowpayments/diagnostic")
    print("   - GET  /api/nowpayments/test-signature")
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
        app.run(debug=False, port=5000, host='0.0.0.0')
    except Exception as e:
        print(f"❌ Erro ao iniciar o servidor Flask: {e}")
