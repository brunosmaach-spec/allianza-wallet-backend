from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import uuid
from database_neon import get_db_connection

staking_bp = Blueprint("staking", __name__)

def get_user_id_from_token():
    from flask import request
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header.split(" ")[1]
    try:
        parts = token.split("_")
        if len(parts) >= 3 and parts[0] == "mock" and parts[1] == "token":
            return int(parts[2])
    except (ValueError, IndexError):
        pass
    return None

# Opções de staking com APYs
staking_options = [
    {"duration": 30, "apy": 120.0, "label": "30 dias", "multiplier": 1.0},
    {"duration": 90, "apy": 180.0, "label": "90 dias", "multiplier": 1.2},
    {"duration": 180, "apy": 250.0, "label": "180 dias", "multiplier": 1.5},
    {"duration": 365, "apy": 400.0, "label": "1 ano", "multiplier": 2.0}
]

def calculate_rewards(amount, duration, apy, auto_compound=False):
    """Calcular recompensas de staking"""
    daily_rate = apy / 365 / 100
    if auto_compound:
        total_amount = amount * ((1 + daily_rate) ** duration)
        return total_amount - amount
    else:
        return amount * daily_rate * duration

@staking_bp.route("/stake", methods=["POST"])
def stake():
    """Fazer staking de tokens"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    amount = float(data.get("amount", 0))
    duration = int(data.get("duration", 30))
    apy = float(data.get("apy", 120.0))
    auto_compound = data.get("auto_compound", False)

    print(f"[STAKING] Requisição recebida - User: {user_id}, Amount: {amount}, Duration: {duration}")

    if amount <= 0:
        return jsonify({"error": "Valor de staking deve ser positivo"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verificar saldo disponível
        cursor.execute("SELECT available FROM balances WHERE user_id = %s AND asset = 'ALZ'", (user_id,))
        balance_result = cursor.fetchone()
        
        if not balance_result or balance_result['available'] < amount:
            return jsonify({"error": "Saldo insuficiente para staking"}), 400

        available_balance = float(balance_result['available'])
        
        cursor.execute("BEGIN")

        # Gerar ID único para o stake
        stake_id = str(uuid.uuid4())
        start_date = datetime.now()
        end_date = start_date + timedelta(days=duration)
        estimated_reward = calculate_rewards(amount, duration, apy, auto_compound)

        print(f"[STAKING] Criando stake: {stake_id}")

        # 1. Registrar no ledger (saída do saldo disponível)
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, "ALZ", -amount, "stake_lock", stake_id, f"Staking de {amount} ALZ por {duration} dias")
        )

        # 2. Atualizar saldos (mover de available para staking_balance)
        cursor.execute(
            "UPDATE balances SET available = available - %s, staking_balance = staking_balance + %s WHERE user_id = %s AND asset = 'ALZ'",
            (amount, amount, user_id)
        )

        # 3. Criar registro de stake
        cursor.execute(
            """INSERT INTO stakes (id, user_id, amount, duration, apy, start_date, end_date, 
                estimated_reward, accrued_reward, status, auto_compound, last_reward_claim, days_remaining) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (stake_id, user_id, amount, duration, apy, start_date, end_date, 
             round(estimated_reward, 6), 0.0, "active", auto_compound, start_date, duration)
        )

        conn.commit()

        new_stake = {
            "id": stake_id,
            "userId": user_id,
            "amount": amount,
            "duration": duration,
            "apy": apy,
            "startDate": start_date.isoformat(),
            "endDate": end_date.isoformat(),
            "estimatedReward": round(estimated_reward, 6),
            "accruedReward": 0.0,
            "status": "active",
            "autoCompound": auto_compound,
            "lastRewardClaim": start_date.isoformat(),
            "daysRemaining": duration
        }

        return jsonify({
            "message": "Staking iniciado com sucesso!", 
            "stake": new_stake
        }), 201

    except Exception as e:
        conn.rollback()
        print(f"[STAKING] Erro: {e}")
        return jsonify({"error": f"Erro ao registrar staking: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/unstake", methods=["POST"])
def unstake():
    """Retirar staking (com penalidade se antecipado)"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    stake_id = data.get("stake_id")
    
    print(f"[UNSTAKE] Requisição - User: {user_id}, Stake: {stake_id}")

    if not stake_id:
        return jsonify({"error": "ID do stake é obrigatório"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM stakes WHERE id = %s AND user_id = %s", (stake_id, user_id))
        stake = cursor.fetchone()
        
        if not stake:
            return jsonify({"error": "Stake não encontrado"}), 404
        
        if stake["status"] != "active":
            return jsonify({"error": "Stake não está ativo"}), 400

        # Calcular penalidade por retirada antecipada
        start_date = stake["start_date"]
        end_date = stake["end_date"]
        now = datetime.now()
        
        days_remaining = (end_date - now).days
        penalty = 0.0
        return_amount = float(stake["amount"])
        accrued_reward = float(stake["accrued_reward"])

        # Aplicar penalidade de 5% se retirada antecipada
        if days_remaining > 0:
            penalty = return_amount * 0.05  # 5% de penalidade
            return_amount -= penalty
            penalty_message = f" (penalidade de 5%: {penalty} ALZ)"
        else:
            penalty_message = ""

        cursor.execute("BEGIN")

        # 1. Registrar no ledger (entrada do valor retornado + recompensas)
        total_return = return_amount + accrued_reward
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, "ALZ", total_return, "unstake", stake_id,
             f"Unstaking de {stake['amount']} ALZ{penalty_message} + {accrued_reward} ALZ de recompensas")
        )

        # 2. Atualizar saldos (mover de staking_balance para available)
        cursor.execute(
            "UPDATE balances SET available = available + %s, staking_balance = staking_balance - %s WHERE user_id = %s AND asset = 'ALZ'",
            (total_return, stake['amount'], user_id)
        )

        # 3. Atualizar status do stake
        cursor.execute(
            "UPDATE stakes SET status = 'withdrawn', accrued_reward = 0, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (stake_id,)
        )

        conn.commit()

        return jsonify({
            "message": "Staking retirado com sucesso!",
            "returned_amount": return_amount,
            "accrued_rewards": accrued_reward,
            "penalty": penalty,
            "total_received": total_return
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"[UNSTAKE] Erro: {e}")
        return jsonify({"error": f"Erro ao retirar staking: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/claim-rewards", methods=["POST"])
def claim_rewards():
    """Coletar recompensas de staking"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    stake_id = data.get("stake_id")
    
    print(f"[CLAIM_REWARDS] Requisição - User: {user_id}, Stake: {stake_id}")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM stakes WHERE id = %s AND user_id = %s", (stake_id, user_id))
        stake = cursor.fetchone()
        
        if not stake:
            return jsonify({"error": "Stake não encontrado"}), 404
        
        if stake["status"] != "active":
            return jsonify({"error": "Stake não está ativo"}), 400
        
        accrued_reward = float(stake["accrued_reward"])
        if accrued_reward <= 0:
            return jsonify({"message": "Nenhuma recompensa para coletar"}), 200

        cursor.execute("BEGIN")

        # 1. Registrar no ledger (entrada das recompensas)
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, "ALZ", accrued_reward, "staking_reward", stake_id, 
             f"Recompensa de staking coletada: {accrued_reward} ALZ")
        )

        # 2. Atualizar saldo disponível
        cursor.execute(
            "UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = 'ALZ'",
            (accrued_reward, user_id)
        )

        # 3. Zerar recompensas acumuladas no stake
        cursor.execute(
            "UPDATE stakes SET accrued_reward = 0, last_reward_claim = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (datetime.now(), stake_id)
        )

        conn.commit()

        return jsonify({
            "message": "Recompensas coletadas com sucesso!",
            "claimed_amount": accrued_reward
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"[CLAIM_REWARDS] Erro: {e}")
        return jsonify({"error": f"Erro ao coletar recompensas: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/me", methods=["GET"])
def get_my_stakes():
    """Buscar stakes do usuário"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM stakes WHERE user_id = %s AND status = 'active'", (user_id,))
        stakes = cursor.fetchall()
        
        # Atualizar recompensas acumuladas
        updated_stakes = []
        for stake in stakes:
            stake_dict = dict(stake)
            
            # Calcular dias restantes
            end_date = stake["end_date"]
            now = datetime.now()
            days_remaining = max(0, (end_date - now).days)
            
            # Calcular recompensas acumuladas desde o último claim
            last_claim = stake["last_reward_claim"]
            days_since_last_claim = (now - last_claim).days
            
            if days_since_last_claim > 0:
                daily_reward = calculate_rewards(stake["amount"], 1, stake["apy"], stake["auto_compound"])
                new_accrued = float(stake["accrued_reward"]) + (daily_reward * days_since_last_claim)
                
                # Atualizar no banco se houver novas recompensas
                if new_accrued > float(stake["accrued_reward"]):
                    cursor.execute(
                        "UPDATE stakes SET accrued_reward = %s, last_reward_claim = %s, days_remaining = %s WHERE id = %s",
                        (new_accrued, now, days_remaining, stake["id"])
                    )
                    stake_dict["accrued_reward"] = new_accrued
                else:
                    stake_dict["accrued_reward"] = float(stake["accrued_reward"])
            else:
                stake_dict["accrued_reward"] = float(stake["accrued_reward"])
            
            stake_dict["days_remaining"] = days_remaining
            updated_stakes.append(stake_dict)
        
        conn.commit()
        
        # Converter para formato do frontend
        formatted_stakes = []
        for stake in updated_stakes:
            formatted_stake = {
                "id": stake["id"],
                "userId": stake["user_id"],
                "amount": float(stake["amount"]),
                "duration": stake["duration"],
                "apy": float(stake["apy"]),
                "startDate": stake["start_date"].isoformat(),
                "endDate": stake["end_date"].isoformat(),
                "estimatedReward": float(stake["estimated_reward"]),
                "accruedReward": float(stake["accrued_reward"]),
                "status": stake["status"],
                "autoCompound": stake["auto_compound"],
                "lastRewardClaim": stake["last_reward_claim"].isoformat(),
                "daysRemaining": stake["days_remaining"]
            }
            formatted_stakes.append(formatted_stake)
        
        return jsonify({"stakes": formatted_stakes}), 200
        
    except Exception as e:
        print(f"[GET_STAKES] Erro: {e}")
        return jsonify({"error": f"Erro ao buscar stakes: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/options", methods=["GET"])
def get_staking_options():
    """Buscar opções de staking disponíveis"""
    return jsonify({"options": staking_options}), 200

@staking_bp.route("/history", methods=["GET"])
def get_staking_history():
    """Buscar histórico de staking do usuário"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT * FROM ledger_entries 
            WHERE user_id = %s AND entry_type IN ('stake_lock', 'unstake', 'staking_reward') 
            ORDER BY created_at DESC""",
            (user_id,)
        )
        history = cursor.fetchall()
        
        return jsonify({"history": [dict(row) for row in history]}), 200
        
    except Exception as e:
        return jsonify({"error": f"Erro ao obter histórico: {e}"}), 500
    finally:
        conn.close()
