# admin_routes.py - VERSÃO FINAL CORRIGIDA
import os
import json
from flask import Blueprint, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

admin_bp = Blueprint('admin', __name__)

# ✅ CONFIGURAÇÃO ÚNICA - Evitar conflitos
def get_db_connection():
    """Conexão única com o banco para evitar conflitos"""
    DATABASE_URL = os.getenv('DATABASE_URL')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL não configurada")
    
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

# ✅ CONSTANTES GLOBAIS - Evitar recálculos
ALZ_PRICE_BRL = 0.10  # 1 ALZ = R$ 0,10
SITE_ADMIN_TOKEN = os.getenv('VITE_SITE_ADMIN_TOKEN', 'allianza_super_admin_2024_CdE25$$$')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({"error": "Token de administrador necessário"}), 401
        
        # ✅ VERIFICAÇÃO DE TOKEN CORRIGIDA
        if token != SITE_ADMIN_TOKEN:
            return jsonify({
                "error": "Token inválido",
                "received": token[:10] + "..." if token else "vazio",
                "expected": SITE_ADMIN_TOKEN[:10] + "..."
            }), 401
        
        return f(*args, **kwargs)
    return decorated_function

# ✅ FUNÇÃO DE CÁLCULO GLOBAL
def calculate_alz_from_brl(amount_brl):
    """Calcula ALZ a partir de BRL de forma consistente"""
    return float(amount_brl) / ALZ_PRICE_BRL

# ✅ ROTA DE HEALTH CHECK MELHORADA
@admin_bp.route('/health', methods=['GET'])
def health_check():
    """Verifica saúde do backend e banco"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Testar conexão com banco
        cursor.execute("SELECT 1 as status")
        db_status = cursor.fetchone()
        
        # Testar tabelas
        cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM payments) as payments_count,
                (SELECT COUNT(*) FROM users) as users_count,
                (SELECT COUNT(*) FROM balances) as balances_count
        """)
        tables_status = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "tables": {
                "payments": tables_status['payments_count'],
                "users": tables_status['users_count'],
                "balances": tables_status['balances_count']
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

# ✅ DASHBOARD CORRIGIDO
@admin_bp.route('/admin/payments', methods=['GET'])
@admin_required
def get_payments():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        print("📥 Buscando pagamentos do banco...")
        
        cursor.execute('''
            SELECT id, email, amount, method, status, created_at, 
                   processed_at, tx_hash, metadata, wallet_address
            FROM payments 
            ORDER BY created_at DESC
        ''')
        payments = cursor.fetchall()
        
        print(f"✅ Encontrados {len(payments)} pagamentos")
        
        # ✅ CORREÇÃO GARANTIDA - Cálculo consistente
        corrected_payments = []
        for payment in payments:
            payment_data = dict(payment)
            amount_brl = float(payment_data['amount'])
            
            # SEMPRE calcular ALZ a partir do BRL
            payment_data['alz_amount'] = calculate_alz_from_brl(amount_brl)
            
            # Log para debug
            print(f"💰 Pagamento {payment_data['id']}: R$ {amount_brl} → {payment_data['alz_amount']} ALZ")
            
            corrected_payments.append(payment_data)
        
        return jsonify({
            "success": True,
            "data": corrected_payments,
            "count": len(corrected_payments),
            "calculation_note": "ALZ = BRL / 0.10 (1 ALZ = R$ 0,10)"
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao carregar pagamentos: {str(e)}")
        return jsonify({"error": f"Erro no servidor: {str(e)}"}), 500
    finally:
        conn.close()

# ✅ PROCESSAMENTO CORRIGIDO
@admin_bp.route('/admin/process-payments', methods=['POST'])
@admin_required
def process_payments():
    data = request.json
    payment_ids = data.get('payment_ids', [])
    admin_user = data.get('admin_user', 'admin')
    
    if not payment_ids:
        return jsonify({"error": "Nenhum pagamento selecionado"}), 400
    
    print(f"🔄 Processando {len(payment_ids)} pagamentos: {payment_ids}")
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("BEGIN")
        processed_count = 0
        errors = []
        
        for payment_id in payment_ids:
            try:
                # ✅ BUSCAR PAGAMENTO COM BLOQUEIO PARA EVITAR CONCORRÊNCIA
                cursor.execute('''
                    SELECT id, email, amount, metadata 
                    FROM payments 
                    WHERE id = %s AND status = 'pending'
                    FOR UPDATE
                ''', (payment_id,))
                
                payment = cursor.fetchone()
                
                if not payment:
                    errors.append(f"Pagamento {payment_id} não encontrado ou já processado")
                    continue
                
                # ✅ CÁLCULO GARANTIDO
                amount_brl = float(payment['amount'])
                alz_amount = calculate_alz_from_brl(amount_brl)
                
                print(f"💰 Processando: R$ {amount_brl} → {alz_amount} ALZ para {payment['email']}")
                
                # ✅ BUSCAR/CRIAR USUÁRIO
                cursor.execute(
                    "SELECT id, wallet_address FROM users WHERE email = %s",
                    (payment['email'],)
                )
                user = cursor.fetchone()
                
                user_id = None
                if user:
                    user_id = user['id']
                    print(f"✅ Usuário encontrado: {user_id}")
                else:
                    # Criar usuário se não existir
                    cursor.execute(
                        "INSERT INTO users (email, created_at) VALUES (%s, NOW()) RETURNING id",
                        (payment['email'],)
                    )
                    user_id = cursor.fetchone()['id']
                    print(f"✅ Novo usuário criado: {user_id}")
                
                # ✅ VERIFICAR/CRIAR BALANCE
                cursor.execute(
                    "SELECT id FROM balances WHERE user_id = %s AND asset = 'ALZ'",
                    (user_id,)
                )
                balance = cursor.fetchone()
                
                if not balance:
                    cursor.execute(
                        "INSERT INTO balances (user_id, asset, available, staking_balance) VALUES (%s, 'ALZ', 0, 0)",
                        (user_id,)
                    )
                    print(f"✅ Balance criado para usuário {user_id}")
                
                # ✅ CREDITAR TOKENS
                cursor.execute(
                    "UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = 'ALZ'",
                    (alz_amount, user_id)
                )
                
                # ✅ REGISTRAR NO LEDGER
                cursor.execute(
                    """INSERT INTO ledger_entries 
                       (user_id, asset, amount, entry_type, description) 
                       VALUES (%s, %s, %s, %s, %s)""",
                    (user_id, 'ALZ', alz_amount, 'purchase', 
                     f'Compra de {alz_amount} ALZ via PIX - R$ {amount_brl}')
                )
                
                # ✅ ATUALIZAR PAGAMENTO
                cursor.execute(
                    """UPDATE payments 
                       SET status = 'completed', 
                           processed_at = NOW(),
                           metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('alz_amount_processed', %s)
                       WHERE id = %s""",
                    (alz_amount, payment_id)
                )
                
                processed_count += 1
                print(f"✅ Pagamento {payment_id} processado com sucesso!")
                
            except Exception as e:
                error_msg = f"Erro no pagamento {payment_id}: {str(e)}"
                errors.append(error_msg)
                print(f"❌ {error_msg}")
                continue
        
        if errors:
            conn.rollback()
            return jsonify({
                "success": False,
                "error": f"Processamento parcialmente falhou",
                "processed_count": processed_count,
                "errors": errors
            }), 400
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"✅ {processed_count} pagamentos processados com sucesso!",
            "processed_count": processed_count,
            "total_alz_distributed": processed_count * alz_amount if processed_count > 0 else 0
        }), 200
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro geral no processamento: {str(e)}")
        return jsonify({"error": f"Erro no servidor: {str(e)}"}), 500
    finally:
        conn.close()

# ✅ ESTATÍSTICAS CORRIGIDAS
@admin_bp.route('/admin/stats', methods=['GET'])
@admin_required
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Supply Total
        TOTAL_SUPPLY = 1000000000
        
        # Tokens em circulação
        cursor.execute("SELECT SUM(available + staking_balance) as circulating FROM balances WHERE asset = 'ALZ'")
        circulating_result = cursor.fetchone()
        circulating = float(circulating_result['circulating'] or 0)
        
        # ✅ PAGAMENTOS PENDENTES CALCULADOS CORRETAMENTE
        cursor.execute("SELECT SUM(amount) as pending_brl FROM payments WHERE status = 'pending'")
        pending_brl_result = cursor.fetchone()
        pending_brl = float(pending_brl_result['pending_brl'] or 0)
        pending_alz = calculate_alz_from_brl(pending_brl)
        
        # Estatísticas
        cursor.execute('''
            SELECT 
                COUNT(*) as total_users,
                (SELECT COUNT(*) FROM payments) as total_payments,
                (SELECT COUNT(*) FROM payments WHERE status = 'completed') as completed_payments,
                (SELECT COUNT(*) FROM payments WHERE status = 'pending') as pending_payments,
                (SELECT SUM(amount) FROM payments WHERE status = 'completed') as total_processed_brl
        ''')
        stats_result = cursor.fetchone()
        
        total_processed_alz = calculate_alz_from_brl(stats_result['total_processed_brl'] or 0)
        
        return jsonify({
            "success": True,
            "stats": {
                "supply": {
                    "total": TOTAL_SUPPLY,
                    "circulating": circulating,
                    "pending_distribution": pending_alz,
                    "reserve": TOTAL_SUPPLY - circulating - pending_alz
                },
                "users": {
                    "total_users": stats_result['total_users']
                },
                "payments": {
                    "total_payments": stats_result['total_payments'],
                    "completed_payments": stats_result['completed_payments'],
                    "pending_payments": stats_result['pending_payments'],
                    "total_processed_brl": pending_brl,
                    "total_processed_alz": total_processed_alz
                }
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Erro nas estatísticas: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ✅ ENVIO MANUAL CORRIGIDO
@admin_bp.route('/admin/manual-token-send', methods=['POST'])
@admin_required
def manual_token_send():
    data = request.json
    email = data.get('email')
    amount = data.get('amount')
    description = data.get('description', 'Crédito administrativo manual')
    
    if not email or not amount:
        return jsonify({"error": "Email e quantidade são obrigatórios"}), 400
    
    try:
        amount_alz = float(amount)
    except ValueError:
        return jsonify({"error": "Quantidade deve ser um número válido"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("BEGIN")
        
        # Buscar ou criar usuário
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            cursor.execute(
                "INSERT INTO users (email, created_at) VALUES (%s, NOW()) RETURNING id",
                (email,)
            )
            user_id = cursor.fetchone()['id']
        else:
            user_id = user['id']
        
        # Verificar balance
        cursor.execute(
            "SELECT id FROM balances WHERE user_id = %s AND asset = 'ALZ'",
            (user_id,)
        )
        balance = cursor.fetchone()
        
        if not balance:
            cursor.execute(
                "INSERT INTO balances (user_id, asset, available, staking_balance) VALUES (%s, 'ALZ', 0, 0)",
                (user_id,)
            )
        
        # Creditar
        cursor.execute(
            "UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = 'ALZ'",
            (amount_alz, user_id)
        )
        
        # Registrar
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description) VALUES (%s, %s, %s, %s, %s)",
            (user_id, 'ALZ', amount_alz, 'manual_credit', description)
        )
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"✅ {amount_alz} ALZ creditados para {email}",
            "amount_alz": amount_alz,
            "email": email
        }), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ✅ DEBUG CORRIGIDO
@admin_bp.route('/admin/debug-token', methods=['GET'])
def debug_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    return jsonify({
        "token_received": token,
        "token_expected": SITE_ADMIN_TOKEN,
        "token_length_received": len(token),
        "token_length_expected": len(SITE_ADMIN_TOKEN),
        "match": token == SITE_ADMIN_TOKEN,
        "message": "Debug de token administrativo"
    }), 200
