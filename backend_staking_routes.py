# backend_staking_routes_improved.py - COM RETIRADA INDIVIDUALIZADA E CARDS - CORRIGIDO CORS
from flask import Blueprint, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
import time
from database_neon import get_db_connection
from functools import wraps

staking_bp = Blueprint('staking', __name__)
CORS(staking_bp, resources={r"/*": {"origins": "*", "supports_credentials": True, "allow_headers": ["Content-Type", "Authorization"]}})

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
    """Convert datetime to timezone-aware (UTC) if needed, handling string dates from DB."""
    if dt is None:
        return None
    
    # Se for uma string, converte para datetime
    if isinstance(dt, str):
        try:
            # Tenta fromisoformat (suporta ISO 8601 com ou sem fuso horário)
            dt_obj = datetime.fromisoformat(dt)
        except ValueError:
            # Tenta formatos comuns se fromisoformat falhar
            try:
                dt_obj = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                try:
                    dt_obj = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # Se tudo falhar, retorna None
                    return None
    elif isinstance(dt, datetime):
        dt_obj = dt
    else:
        # Se não for string nem datetime, retorna None
        return None
        
    # Se for naive, torna-o aware em UTC
    if dt_obj.tzinfo is None:
        return dt_obj.replace(tzinfo=timezone.utc)
    
    # Se for aware, converte para UTC
    return dt_obj.astimezone(timezone.utc)

def calculate_staking_rewards(stake_amount, apy, start_date, last_claim_date=None):
    """Calculate staking rewards based on time elapsed"""
    now = datetime.now(timezone.utc)
    
    if last_claim_date:
        start_calc = safe_datetime_aware(last_claim_date)
    else:
        start_calc = safe_datetime_aware(start_date)
        
    if start_calc is None:
        # Se a data de início for None, não há como calcular. Retorna 0.
        return 0, 0
    
    # Calculate days elapsed
    days_elapsed = (now - start_calc).total_seconds() / (24 * 3600)
    
    # Calculate rewards (APY is annual, so divide by 365 for daily)
    daily_rate = apy / 365
    rewards = stake_amount * daily_rate * days_elapsed
    
    return max(rewards, 0), days_elapsed

def calculate_days_remaining(end_date):
    """Calculate days remaining until maturity"""
    now = datetime.now(timezone.utc)
    end_date_aware = safe_datetime_aware(end_date)
    
    if end_date_aware is None:
        return 0
        
    # now já é timezone-aware (UTC)
    days_remaining = (end_date_aware - now).total_seconds() / (24 * 3600)
    return max(days_remaining, 0)

def build_stake_card(stake_dict, plan_config):
    """Build a detailed card object for a stake with all relevant information"""
    start_date = safe_datetime_aware(stake_dict['start_date'])
    end_date = safe_datetime_aware(stake_dict['end_date'])
    current_time = datetime.now(timezone.utc)
    
    # Calculate current rewards
    pending_rewards, days_elapsed = calculate_staking_rewards(
        stake_dict['amount'],
        plan_config['apy'],
        start_date,
        safe_datetime_aware(stake_dict.get('last_reward_claim')) if stake_dict.get('last_reward_claim') else None
    )
    
    # Calculate days remaining
    days_remaining = calculate_days_remaining(end_date)
    is_mature = current_time >= end_date
    is_early = current_time < end_date
    
    # Calculate penalty if early withdrawal
    penalty_amount = 0
    penalty_percentage = 0
    if is_early:
        penalty_percentage = plan_config['early_unstake_penalty'] * 100
        penalty_amount = stake_dict['amount'] * plan_config['early_unstake_penalty']
    
    # Calculate final amounts
    amount_after_penalty = stake_dict['amount'] - penalty_amount
    total_with_rewards = amount_after_penalty + pending_rewards if not is_early else amount_after_penalty
    
    return {
        "stake_id": stake_dict['id'],
        "amount": float(stake_dict['amount']),
        "staking_plan": stake_dict['staking_plan'],
        "plan_name": plan_config['name'],
        "apy": plan_config['apy'] * 100,  # Convert to percentage
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "status": stake_dict['status'],
        "is_mature": is_mature,
        "is_early": is_early,
        "days_elapsed": round(days_elapsed, 2),
        "days_remaining": round(days_remaining, 2),
        "current_rewards": float(pending_rewards),
        "total_rewards_claimed": float(stake_dict.get('total_rewards_claimed') or 0),
        "penalty": {
            "percentage": penalty_percentage,
            "amount": float(penalty_amount),
            "applies": is_early
        },
        "withdrawal_preview": {
            "original_amount": float(stake_dict['amount']),
            "penalty_deducted": float(penalty_amount),
            "amount_after_penalty": float(amount_after_penalty),
            "rewards_to_receive": float(pending_rewards if not is_early else 0),
            "total_to_receive": float(total_with_rewards),
            "message": "Retirada no prazo - sem penalidade" if is_mature else f"Retirada antecipada - {penalty_percentage:.1f}% de penalidade"
        }
    }


@staking_bp.route('/staking/stake', methods=['OPTIONS'])
def create_stake_options():
    return '', 200

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
            
            # Criar stake com ID único
            stake_id = f"stake_{user_id}_{int(time.time() * 1000)}"
            
            cursor.execute('''
                INSERT INTO stakes (id, user_id, amount, staking_plan, start_date, end_date, status, last_reward_claim)
                VALUES (%s, %s, %s, %s, %s, %s, 'active', %s)
            ''', (stake_id, user_id, amount, staking_plan, start_date, end_date, start_date))
            
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


@token_required
def get_active_stakes():
    """Get all active stakes with detailed cards for withdrawal preview"""
    try:
        user_id = request.user_id
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch all active stakes
        cursor.execute('''
            SELECT id, amount, staking_plan, start_date, end_date, status, 
                   last_reward_claim, total_rewards_claimed
            FROM stakes 
            WHERE user_id = %s AND status = 'active'
            ORDER BY start_date DESC
        ''', (user_id,))
        
        stakes = cursor.fetchall()
        conn.close()
        
        stakes_cards = []
        total_staked = 0
        total_pending_rewards = 0
        
        for stake in stakes:
            stake_dict = dict(stake)
            plan_config = STAKING_PLANS[stake_dict['staking_plan']]
            
            card = build_stake_card(stake_dict, plan_config)
            stakes_cards.append(card)
            
            total_staked += stake_dict['amount']
            total_pending_rewards += card['current_rewards']
        
        return jsonify({
            "success": True,
            "stakes": stakes_cards,
            "summary": {
                "total_active_stakes": len(stakes_cards),
                "total_staked": float(total_staked),
                "total_pending_rewards": float(total_pending_rewards)
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar stakes ativos: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/withdrawal-preview/<stake_id>', methods=['GET', 'OPTIONS'])
@token_required
def get_withdrawal_preview(stake_id):
    """Get detailed preview of what will be received on withdrawal"""
    try:
        user_id = request.user_id
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch the stake
        cursor.execute('''
            SELECT id, user_id, amount, staking_plan, start_date, end_date, status, 
                   last_reward_claim, total_rewards_claimed
            FROM stakes 
            WHERE id = %s AND user_id = %s
        ''', (stake_id, user_id))
        
        stake = cursor.fetchone()
        conn.close()
        
        if not stake:
            return jsonify({"error": "Stake não encontrado"}), 404
        
        if stake['status'] != 'active':
            return jsonify({"error": "Stake não está ativo"}), 400
        
        stake_dict = dict(stake)
        plan_config = STAKING_PLANS[stake_dict['staking_plan']]
        
        card = build_stake_card(stake_dict, plan_config)
        
        return jsonify({
            "success": True,
            "card": card
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar preview de retirada: {e}")
        return jsonify({"error": str(e)}), 500


        
    try:
        user_id = request.user_id
        # stake_id já está na URL (passado como argumento da função)
        
        if not stake_id:
            return jsonify({"error": "Stake ID é obrigatório"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("BEGIN")
            
            # Buscar o stake
            cursor.execute('''
                SELECT id, user_id, amount, staking_plan, start_date, end_date, status, total_rewards_claimed, last_reward_claim
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
                    withdrawn_at = %s,
                    actual_return = %s,
                    penalty_applied = %s,
                    total_rewards_claimed = %s
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
            
            # Build response with detailed card info
            card = build_stake_card(stake_dict, plan_config)
            
            return jsonify({
                "success": True,
                "message": f"Unstake realizado! Recebido: {total_to_receive:.2f} ALZ",
                "stake_card": card,
                "withdrawal_details": {
                    "original_amount": float(stake_dict['amount']),
                    "amount_received": float(total_to_receive),
                    "rewards_claimed": float(rewards_to_claim),
                    "penalty_applied": float(penalty_amount),
                    "penalty_percentage": (plan_config['early_unstake_penalty'] * 100) if is_early else 0,
                    "was_early": is_early,
                    "days_held": round(days_elapsed, 2)
                }
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

@staking_bp.route('/staking/claim-rewards', methods=['POST', 'OPTIONS'])
@token_required
def claim_staking_rewards():
    """Claim staking rewards for a specific stake"""
    try:
        user_id = request.user_id
        # stake_id já está na URL (passado como argumento da função)
        
        if not stake_id:
            return jsonify({"error": "Stake ID é obrigatório"}), 400
        
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
            last_claim_date = safe_datetime_aware(stake["last_reward_claim"])
            
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
                "rewards_claimed": float(rewards),
                "days_elapsed": round(days_elapsed, 2),
                "total_rewards_claimed": float(total_rewards)
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


@staking_bp.route('/active-stakes', methods=['OPTIONS'])
def active_stakes_options():
    return '', 200

@staking_bp.route('/active-stakes', methods=['GET'])
@token_required
def get_my_stakes():
    """Get user's staking positions with detailed cards"""
    try:
        user_id = request.user_id
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, amount, staking_plan, start_date, end_date, status, 
                   last_reward_claim, total_rewards_claimed, withdrawn_at,
                   actual_return, penalty_applied
            FROM stakes 
            WHERE user_id = %s
            ORDER BY start_date DESC
        ''', (user_id,))
        
        stakes = cursor.fetchall()
        conn.close()
        
        active_stakes_cards = []
        completed_stakes_cards = []
        total_staked = 0
        total_rewards = 0
        total_pending_rewards = 0
        
        for stake in stakes:
            stake_dict = dict(stake)
            
            if stake_dict['status'] == 'active':
                plan_config = STAKING_PLANS[stake_dict['staking_plan']]
                card = build_stake_card(stake_dict, plan_config)
                active_stakes_cards.append(card)
                
                total_staked += stake_dict['amount']
                total_pending_rewards += card['current_rewards']
            else:
                # For completed stakes, show simpler info
                plan_config = STAKING_PLANS[stake_dict['staking_plan']]
                completed_stakes_cards.append({
                    "stake_id": stake_dict['id'],
                    "amount": float(stake_dict['amount']),
                    "staking_plan": stake_dict['staking_plan'],
                    "plan_name": plan_config['name'],
                    "start_date": safe_datetime_aware(stake_dict['start_date']).isoformat() if stake_dict['start_date'] else None,
                    "end_date": safe_datetime_aware(stake_dict['end_date']).isoformat() if stake_dict['end_date'] else None,
                    "withdrawn_at": safe_datetime_aware(stake_dict['withdrawn_at']).isoformat() if stake_dict['withdrawn_at'] else None,
                    "actual_return": float(stake_dict['actual_return']) if stake_dict['actual_return'] else None,
                    "penalty_applied": float(stake_dict['penalty_applied']) if stake_dict['penalty_applied'] else None,
                    "total_rewards_claimed": float(stake_dict['total_rewards_claimed'] or 0)
                })
            
            total_rewards += stake_dict['total_rewards_claimed'] or 0
        
        return jsonify({
            "success": True,
            "active_stakes": active_stakes_cards,
            "completed_stakes": completed_stakes_cards,
            "summary": {
                "total_active_stakes": len(active_stakes_cards),
                "total_completed_stakes": len(completed_stakes_cards),
                "total_staked": float(total_staked),
                "total_rewards_claimed": float(total_rewards),
                "total_pending_rewards": float(total_pending_rewards)
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar stakes: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/options', methods=['OPTIONS'])
def staking_options_options():
    return '', 200

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
                "apy": plan_config['apy'] * 100,  # Convert to percentage
                "min_amount": plan_config['min_amount'],
                "early_unstake_penalty": plan_config['early_unstake_penalty'] * 100  # Convert to percentage
            })
        
        return jsonify({
            "success": True,
            "options": options
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar opções: {e}")
        return jsonify({"error": str(e)}), 500

@staking_bp.route('/staking/stats', methods=['OPTIONS'])
def staking_stats_options():
    return '', 200

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
        
        conn.close()
        
        return jsonify({
            "success": True,
            "stats": {
                "total_staked": float(total_staked),
                "total_rewards_claimed": float(total_rewards),
                "active_stakes": active_stakes,
                "estimated_annual_rewards": float(estimated_annual),
                "estimated_monthly_rewards": float(estimated_annual / 12)
            }
        }), 200
        
    except Exception as e:
        print(f"❌ Erro ao buscar estatísticas: {e}")
        return jsonify({"error": str(e)}), 500
