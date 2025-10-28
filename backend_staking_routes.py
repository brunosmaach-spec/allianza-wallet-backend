# backend_staking_routes.py - CORRIGIDO
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone
import time
from database_neon import get_db_connection
from functools import wraps

staking_bp = Blueprint('staking', __name__)

# Configurações de Staking
STAKING_PLANS = {
    '30_days': {
        'name': '30 Dias',
        'duration_days': 30,
        'apy': 0.10,  # 10% APY
        'min_amount': 1000,
        'early_unstake_penalty': 0.20  # 20% penalty
    },
    '90_days': {
        'name': '90 Dias', 
        'duration_days': 90,
        'apy': 0.25,  # 25% APY
        'min_amount': 5000,
        'early_unstake_penalty': 0.15  # 15% penalty
    },
    '180_days': {
        'name': '180 Dias',
        'duration_days': 180, 
        'apy': 0.60,  # 60% APY
        'min_amount': 10000,
        'early_unstake_penalty': 0.10  # 10% penalty
    },
    '365_days': {
        'name': '365 Dias',
        'duration_days': 365,
        'apy': 1.20,  # 120% APY
        'min_amount': 20000,
        'early_unstake_penalty': 0.05  # 5% penalty
    }
}

# Middleware de autenticação
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

def get_user_id_from_token(token):
    try:
        parts = token.split("_")
        if len(parts) >= 3 and parts[0] == "mock" and parts[1] == "token":
            return int(parts[2])
    except (ValueError, IndexError):
        pass
    return None

def safe_datetime_aware(dt):
    """Convert datetime to timezone-aware if needed"""
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def calculate_staking_rewards(stake_amount, apy, start_date, last_claim_date=None):
    """Calculate staking rewards based on time elapsed"""
    now = datetime.now(timezone.utc)
    
    if last_claim_date:
        start_calc = last_claim_date
    else:
        start_calc = start_date
    
    # Calculate days elapsed
    days_elapsed = (now - start_calc).total_seconds() / (24 * 3600)
    
    # Calculate rewards (APY is annual, so divide by 365 for daily)
    daily_rate = apy / 365
    rewards = stake_amount * daily_rate * days_elapsed
    
    return max(rewards, 0), days_elapsed

@staking_bp.route('/staking/stake', methods=['POST'])
@token_required
def create_stake():
    """Create a new staking position"""
    try:
        user_id = request.user_id
        data = request.json
        amount = data.get('amount')
        staking_plan = data.get('staking_plan')
        
        if not amount or not staking_plan:
            return jsonify({"error": "Amount e staking_plan são obrigatórios"}), 400
        
        if staking_plan not in STAKING_PLANS:
            return jsonify({"error": "Plano de staking inválido"}), 400
        
        plan_config = STAKING_PLANS[staking_plan]
        amount = float(amount)
        
        if amount < plan_config['min_amount']:
            return jsonify({"error": f"Valor mínimo para este plano é {plan_config['min_amount']} ALZ"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("BEGIN")
            
            # Verificar saldo disponível
            cursor.execute("SELECT available FROM balances WHERE user_id = %s AND asset = 'ALZ'", (user_id,))
            balance = cursor.fetchone()
            
            if not balance or float(balance['available']) < amount:
                return jsonify({"error": "Saldo insuficiente"}), 400
            
            # Calcular data de término
            start_date = datetime.now(timezone.utc)
            end_date = start_date + timedelta(days=plan_config['duration_days'])
            
            # Criar stake
            cursor.execute('''
                INSERT INTO stakes (user_id, amount, staking_plan, start_date, end_date, status)
                VALUES (%s, %s, %s, %s, %s, 'active')
                RETURNING id
            ''', (user_id, amount, staking_plan, start_date, end_date))
            
            stake_id = cursor.fetchone()['id']
            
            # Atualizar saldos
            cursor.execute('''
                UPDATE balances 
                SET available = available - %s, staking_balance = staking_balance + %s
                WHERE user_id = %s AND asset = 'ALZ'
            ''', (amount, amount, user_id))
            
            # Registrar no ledger
            cursor.execute('''
                INSERT INTO ledger_entries 
                (user_id, asset, amount, entry_type, description, idempotency_key)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (user_id, 'ALZ', amount, 'staking_lock', 
                  f'Staking {amount} ALZ - Plano {plan_config["name"]}', 
                  f'stake_{stake_id}_{int(time.time())}'))
            
            conn.commit()
            
            return jsonify({
                "success": True,
                "message": f"Staking de {amount} ALZ criado com sucesso!",
                "stake_id": stake_id,
                "end_date": end_date.isoformat(),
                "estimated_rewards": amount * plan_config['apy']
            }), 200
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Erro ao criar stake: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Erro geral create-stake: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/unstake', methods=['POST'])
@token_required
def unstake():
    """Unstake tokens (early or at maturity)"""
    try:
        user_id = request.user_id
        data = request.json
        stake_id = data.get('stake_id')
        
        if not stake_id:
            return jsonify({"error": "stake_id é obrigatório"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("BEGIN")
            
            # Buscar o stake
            cursor.execute('''
                SELECT id, user_id, amount, staking_plan, start_date, end_date, status, total_rewards_claimed
                FROM stakes 
                WHERE id = %s AND user_id = %s
            ''', (stake_id, user_id))
            
            stake = cursor.fetchone()
            
            if not stake:
                return jsonify({"error": "Stake não encontrado"}), 404
            
            if stake['status'] != 'active':
                return jsonify({"error": "Stake não está ativo"}), 400
            
            stake_dict = dict(stake)
            plan_config = STAKING_PLANS[stake_dict['staking_plan']]
            current_time = datetime.now(timezone.utc)
            end_date = safe_datetime_aware(stake_dict['end_date'])
            
            # Calcular recompensas pendentes
            pending_rewards, days_elapsed = calculate_staking_rewards(
                stake_dict['amount'], 
                plan_config['apy'],
                safe_datetime_aware(stake_dict['start_date']),
                safe_datetime_aware(stake_dict.get('last_reward_claim')) if stake_dict.get('last_reward_claim') else None
            )
            
            # Verificar se é early unstake
            is_early = current_time < end_date
            penalty_amount = 0
            
            if is_early:
                penalty_amount = stake_dict['amount'] * plan_config['early_unstake_penalty']
                final_amount = stake_dict['amount'] - penalty_amount
                rewards_to_claim = 0  # No rewards for early unstake
            else:
                final_amount = stake_dict['amount']
                rewards_to_claim = pending_rewards
            
            total_to_receive = final_amount + rewards_to_claim
            
            # Atualizar saldos
            cursor.execute('''
                UPDATE balances 
                SET available = available + %s, staking_balance = staking_balance - %s
                WHERE user_id = %s AND asset = 'ALZ'
            ''', (total_to_receive, stake_dict['amount'], user_id))
            
            # Atualizar status do stake
            cursor.execute('''
                UPDATE stakes 
                SET status = 'completed', 
                    unstake_date = %s,
                    final_amount = %s,
                    penalty_applied = %s,
                    rewards_claimed_at_unstake = %s
                WHERE id = %s
            ''', (current_time, final_amount, penalty_amount, rewards_to_claim, stake_id))
            
            # Registrar no ledger
            if rewards_to_claim > 0:
                cursor.execute('''
                    INSERT INTO ledger_entries 
                    (user_id, asset, amount, entry_type, description, idempotency_key)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (user_id, 'ALZ', rewards_to_claim, 'staking_reward', 
                      f'Recompensas de staking - Stake {stake_id}', 
                      f'reward_{stake_id}_{int(time.time())}'))
            
            cursor.execute('''
                INSERT INTO ledger_entries 
                (user_id, asset, amount, entry_type, description, idempotency_key)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (user_id, 'ALZ', final_amount, 'staking_unlock', 
                  f'Unstake {final_amount} ALZ - Stake {stake_id}', 
                  f'unstake_{stake_id}_{int(time.time())}'))
            
            if penalty_amount > 0:
                cursor.execute('''
                    INSERT INTO ledger_entries 
                    (user_id, asset, amount, entry_type, description, idempotency_key)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (user_id, 'ALZ', -penalty_amount, 'staking_penalty', 
                      f'Penalidade early unstake - Stake {stake_id}', 
                      f'penalty_{stake_id}_{int(time.time())}'))
            
            conn.commit()
            
            return jsonify({
                "success": True,
                "message": f"Unstake realizado! Recebido: {total_to_receive:.2f} ALZ",
                "amount_received": total_to_receive,
                "original_amount": stake_dict['amount'],
                "rewards_claimed": rewards_to_claim,
                "penalty_applied": penalty_amount,
                "was_early": is_early
            }), 200
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Erro ao processar unstake: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Erro geral unstake: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/claim-rewards', methods=['POST'])
@token_required
def claim_staking_rewards():
    """Claim staking rewards for a specific stake"""
    try:
        user_id = request.user_id
        data = request.json
        stake_id = data.get('stake_id')
        
        if not stake_id:
            return jsonify({"error": "stake_id é obrigatório"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("BEGIN")
            
            # Buscar o stake
            cursor.execute('''
                SELECT id, user_id, amount, staking_plan, start_date, last_reward_claim, total_rewards_claimed
                FROM stakes 
                WHERE id = %s AND user_id = %s AND status = 'active'
            ''', (stake_id, user_id))
            
            stake = cursor.fetchone()
            
            if not stake:
                return jsonify({"error": "Stake não encontrado ou não ativo"}), 404
            
            stake_dict = dict(stake)
            last_claim_date = safe_datetime_aware(stake["last_reward_claim"])  # ✅ CORREÇÃO DA INDENTAÇÃO
            
            plan_config = STAKING_PLANS[stake_dict['staking_plan']]
            
            # Calcular recompensas
            rewards, days_elapsed = calculate_staking_rewards(
                stake_dict['amount'], 
                plan_config['apy'],
                safe_datetime_aware(stake_dict['start_date']),
                last_claim_date
            )
            
            if rewards <= 0:
                return jsonify({"error": "Nenhuma recompensa disponível para resgate"}), 400
            
            # Atualizar saldo
            cursor.execute('''
                UPDATE balances 
                SET available = available + %s
                WHERE user_id = %s AND asset = 'ALZ'
            ''', (rewards, user_id))
            
            # Atualizar stake
            current_time = datetime.now(timezone.utc)
            total_rewards = (stake_dict['total_rewards_claimed'] or 0) + rewards
            
            cursor.execute('''
                UPDATE stakes 
                SET last_reward_claim = %s, total_rewards_claimed = %s
                WHERE id = %s
            ''', (current_time, total_rewards, stake_id))
            
            # Registrar no ledger
            cursor.execute('''
                INSERT INTO ledger_entries 
                (user_id, asset, amount, entry_type, description, idempotency_key)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (user_id, 'ALZ', rewards, 'staking_reward', 
                  f'Recompensas de staking - {days_elapsed:.1f} dias - Stake {stake_id}', 
                  f'reward_claim_{stake_id}_{int(time.time())}'))
            
            conn.commit()
            
            return jsonify({
                "success": True,
                "message": f"Recompensas de {rewards:.2f} ALZ resgatadas com sucesso!",
                "rewards_claimed": rewards,
                "days_elapsed": days_elapsed,
                "total_rewards_claimed": total_rewards
            }), 200
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Erro ao processar recompensas: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Erro geral claim-rewards: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/me', methods=['GET'])
@token_required
def get_my_stakes():
    """Get user's staking positions"""
    try:
        user_id = request.user_id
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, amount, staking_plan, start_date, end_date, status, 
                   last_reward_claim, total_rewards_claimed, unstake_date,
                   final_amount, penalty_applied, rewards_claimed_at_unstake
            FROM stakes 
            WHERE user_id = %s
            ORDER BY created_at DESC
        ''', (user_id,))
        
        stakes = cursor.fetchall()
        
        stakes_list = []
        total_staked = 0
        total_rewards = 0
        total_pending_rewards = 0
        
        for stake in stakes:
            stake_dict = dict(stake)
            
            # Calcular recompensas pendentes para stakes ativos
            pending_rewards = 0
            if stake_dict['status'] == 'active':
                plan_config = STAKING_PLANS[stake_dict['staking_plan']]
                pending_rewards, days_elapsed = calculate_staking_rewards(
                    stake_dict['amount'], 
                    plan_config['apy'],
                    safe_datetime_aware(stake_dict['start_date']),
                    safe_datetime_aware(stake_dict['last_reward_claim']) if stake_dict['last_reward_claim'] else None
                )
                total_pending_rewards += pending_rewards
                total_staked += stake_dict['amount']
            
            total_rewards += stake_dict['total_rewards_claimed'] or 0
            
            stakes_list.append({
                "id": stake_dict['id'],
                "amount": float(stake_dict['amount']),
                "staking_plan": stake_dict['staking_plan'],
                "plan_name": STAKING_PLANS[stake_dict['staking_plan']]['name'],
                "start_date": stake_dict['start_date'].isoformat() if stake_dict['start_date'] else None,
                "end_date": stake_dict['end_date'].isoformat() if stake_dict['end_date'] else None,
                "status": stake_dict['status'],
                "last_reward_claim": stake_dict['last_reward_claim'].isoformat() if stake_dict['last_reward_claim'] else None,
                "total_rewards_claimed": float(stake_dict['total_rewards_claimed'] or 0),
                "pending_rewards": pending_rewards,
                "unstake_date": stake_dict['unstake_date'].isoformat() if stake_dict['unstake_date'] else None,
                "final_amount": float(stake_dict['final_amount']) if stake_dict['final_amount'] else None,
                "penalty_applied": float(stake_dict['penalty_applied']) if stake_dict['penalty_applied'] else None
            })
        
        return jsonify({
            "success": True,
            "stakes": stakes_list,
            "summary": {
                "total_staked": total_staked,
                "total_rewards_claimed": total_rewards,
                "total_pending_rewards": total_pending_rewards,
                "active_stakes": len([s for s in stakes_list if s['status'] == 'active'])
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar stakes: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@staking_bp.route('/staking/options', methods=['GET'])
def get_staking_options():
    """Get available staking plans"""
    try:
        options = []
        for plan_key, plan_config in STAKING_PLANS.items():
            options.append({
                "key": plan_key,
                "name": plan_config['name'],
                "duration_days": plan_config['duration_days'],
                "apy": plan_config['apy'],
                "min_amount": plan_config['min_amount'],
                "early_unstake_penalty": plan_config['early_unstake_penalty']
            })
        
        return jsonify({
            "success": True,
            "options": options
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar opções: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/stats', methods=['GET'])
@token_required
def get_staking_stats():
    """Get staking statistics for user"""
    try:
        user_id = request.user_id
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total staked
        cursor.execute('''
            SELECT COALESCE(SUM(amount), 0) as total_staked
            FROM stakes 
            WHERE user_id = %s AND status = 'active'
        ''', (user_id,))
        total_staked = cursor.fetchone()['total_staked']
        
        # Total rewards claimed
        cursor.execute('''
            SELECT COALESCE(SUM(total_rewards_claimed), 0) as total_rewards
            FROM stakes 
            WHERE user_id = %s
        ''', (user_id,))
        total_rewards = cursor.fetchone()['total_rewards']
        
        # Active stakes count
        cursor.execute('''
            SELECT COUNT(*) as active_stakes
            FROM stakes 
            WHERE user_id = %s AND status = 'active'
        ''', (user_id,))
        active_stakes = cursor.fetchone()['active_stakes']
        
        # Estimated annual rewards
        estimated_annual = 0
        if total_staked > 0:
            cursor.execute('''
                SELECT staking_plan, SUM(amount) as amount
                FROM stakes 
                WHERE user_id = %s AND status = 'active'
                GROUP BY staking_plan
            ''', (user_id,))
            
            active_stakes_by_plan = cursor.fetchall()
            
            for stake in active_stakes_by_plan:
                plan_config = STAKING_PLANS[stake['staking_plan']]
                estimated_annual += stake['amount'] * plan_config['apy']
        
        return jsonify({
            "success": True,
            "stats": {
                "total_staked": float(total_staked),
                "total_rewards_claimed": float(total_rewards),
                "active_stakes": active_stakes,
                "estimated_annual_rewards": estimated_annual,
                "estimated_monthly_rewards": estimated_annual / 12
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar estatísticas: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@staking_bp.route('/staking/auto-compound/<stake_id>', methods=['PUT'])
@token_required
def toggle_auto_compound(stake_id):
    """Toggle auto-compound for a stake"""
    try:
        user_id = request.user_id
        data = request.json
        auto_compound = data.get('auto_compound', False)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar se o stake pertence ao usuário
        cursor.execute('''
            SELECT id FROM stakes WHERE id = %s AND user_id = %s
        ''', (stake_id, user_id))
        
        if not cursor.fetchone():
            return jsonify({"error": "Stake não encontrado"}), 404
        
        # Atualizar auto-compound
        cursor.execute('''
            UPDATE stakes SET auto_compound = %s WHERE id = %s
        ''', (auto_compound, stake_id))
        
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"Auto-compound {'ativado' if auto_compound else 'desativado'} com sucesso",
            "auto_compound": auto_compound
        }), 200
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro ao atualizar auto-compound: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
