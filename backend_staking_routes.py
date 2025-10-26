# backend_staking_routes.py - CORREÇÃO COMPLETA DA FUNÇÃO safe_datetime_diff
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone
import uuid
import math
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

# ✅ OPÇÕES DE STAKING MELHORADAS - APYs COMPETITIVOS
staking_options = [
    {"duration": 7, "apy": 80.0, "label": "7 dias", "multiplier": 0.8, "early_withdrawal_penalty": 0.10},
    {"duration": 30, "apy": 120.0, "label": "30 dias", "multiplier": 1.0, "early_withdrawal_penalty": 0.08},
    {"duration": 90, "apy": 180.0, "label": "90 dias", "multiplier": 1.2, "early_withdrawal_penalty": 0.05},
    {"duration": 180, "apy": 250.0, "label": "180 dias", "multiplier": 1.5, "early_withdrawal_penalty": 0.03},
    {"duration": 365, "apy": 400.0, "label": "1 ano", "multiplier": 2.0, "early_withdrawal_penalty": 0.02},
]

# ✅ TOKENS SUPORTADOS PARA STAKING
supported_tokens = {
    "ALZ": {"name": "Allianza Token", "min_stake": 10.0, "apy_boost": 1.2},
    "BTC": {"name": "Bitcoin", "min_stake": 0.001, "apy_boost": 1.0},
    "ETH": {"name": "Ethereum", "min_stake": 0.01, "apy_boost": 1.0},
    "ADA": {"name": "Cardano", "min_stake": 100.0, "apy_boost": 1.1},
    "SOL": {"name": "Solana", "min_stake": 1.0, "apy_boost": 1.15},
    "DOT": {"name": "Polkadot", "min_stake": 10.0, "apy_boost": 1.1},
}

def calculate_compounded_rewards(amount, duration, apy, auto_compound=False):
    """Calcular recompensas com compound automático"""
    daily_rate = apy / 365 / 100
    
    if auto_compound:
        total_amount = amount * ((1 + daily_rate) ** duration)
        return total_amount - amount
    else:
        return amount * daily_rate * duration

def calculate_actual_apy(base_apy, token, duration, auto_compound):
    """Calcular APY real considerando boosts e compound"""
    token_boost = supported_tokens.get(token, {}).get("apy_boost", 1.0)
    duration_boost = 1.0 + (duration / 365) * 0.5
    
    base_rate = base_apy * token_boost * duration_boost
    
    if auto_compound:
        daily_rate = base_rate / 365 / 100
        compounded_apy = ((1 + daily_rate) ** 365 - 1) * 100
        return min(compounded_apy, 1000.0)
    else:
        return base_rate

def safe_datetime_diff(dt1, dt2):
    """✅✅✅ CORREÇÃO CRÍTICA: Calcular diferença entre datetimes de forma segura"""
    try:
        # Se ambos são naive (sem timezone), converter para UTC timezone-aware
        if dt1.tzinfo is None and dt2.tzinfo is None:
            dt1 = dt1.replace(tzinfo=timezone.utc)
            dt2 = dt2.replace(tzinfo=timezone.utc)
        
        # Se um tem timezone e o outro não, converter o naive para UTC
        elif dt1.tzinfo is None and dt2.tzinfo is not None:
            dt1 = dt1.replace(tzinfo=timezone.utc)
        elif dt1.tzinfo is not None and dt2.tzinfo is None:
            dt2 = dt2.replace(tzinfo=timezone.utc)
        
        # Agora ambos têm timezone, normalizar para UTC
        dt1_utc = dt1.astimezone(timezone.utc)
        dt2_utc = dt2.astimezone(timezone.utc)
        
        # Retornar a diferença
        return dt1_utc - dt2_utc
        
    except Exception as e:
        print(f"❌ Erro em safe_datetime_diff: {e}")
        # Fallback: converter ambos para naive
        if hasattr(dt1, 'replace'):
            dt1 = dt1.replace(tzinfo=None)
        if hasattr(dt2, 'replace'):
            dt2 = dt2.replace(tzinfo=None)
        return dt1 - dt2

def safe_days_remaining(end_date, current_date=None):
    """✅ CORREÇÃO: Calcular dias restantes de forma segura"""
    if current_date is None:
        current_date = datetime.now(timezone.utc)
    
    try:
        # Usar a função safe_datetime_diff corrigida
        time_diff = safe_datetime_diff(end_date, current_date)
        days = time_diff.days
        
        # Se a diferença for negativa, significa que já passou da data
        if days < 0:
            return 0
        
        # Se for menos de 1 dia mas ainda não passou, considerar 1 dia
        if time_diff.total_seconds() > 0:
            return max(1, days)
        else:
            return 0
            
    except Exception as e:
        print(f"❌ Erro em safe_days_remaining: {e}")
        return 0

@staking_bp.route("/stake", methods=["POST"])
def stake():
    """Fazer staking de tokens"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    amount = float(data.get("amount", 0))
    duration = int(data.get("duration", 30))
    token = data.get("token", "ALZ")
    auto_compound = data.get("auto_compound", False)

    print(f"[STAKING] Requisição recebida - User: {user_id}, Amount: {amount}, Token: {token}, Duration: {duration}")

    if amount <= 0:
        return jsonify({"error": "Valor de staking deve ser positivo"}), 400

    if token not in supported_tokens:
        return jsonify({"error": f"Token {token} não suportado para staking"}), 400

    min_stake = supported_tokens[token]["min_stake"]
    if amount < min_stake:
        return jsonify({"error": f"Valor mínimo para staking de {token} é {min_stake}"}), 400

    staking_option = next((opt for opt in staking_options if opt["duration"] == duration), None)
    if not staking_option:
        return jsonify({"error": "Duração de staking não suportada"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT available FROM balances WHERE user_id = %s AND asset = %s", (user_id, token))
        balance_result = cursor.fetchone()
        
        if not balance_result or balance_result['available'] < amount:
            return jsonify({"error": f"Saldo insuficiente de {token} para staking"}), 400

        cursor.execute("BEGIN")

        base_apy = staking_option["apy"]
        actual_apy = calculate_actual_apy(base_apy, token, duration, auto_compound)
        estimated_reward = calculate_compounded_rewards(amount, duration, actual_apy, auto_compound)

        stake_id = f"stk_{uuid.uuid4().hex[:16]}"
        start_date = datetime.now(timezone.utc)
        end_date = start_date + timedelta(days=duration)

        print(f"[STAKING] Criando stake: {stake_id} - APY: {actual_apy:.2f}%")

        # 1. Registrar no ledger
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, token, -amount, "stake_lock", stake_id, 
             f"Staking de {amount} {token} por {duration} dias (APY: {actual_apy:.2f}%)")
        )

        # 2. Atualizar saldos
        cursor.execute(
            "UPDATE balances SET available = available - %s, staking_balance = staking_balance + %s WHERE user_id = %s AND asset = %s",
            (amount, amount, user_id, token)
        )

        # 3. Criar registro de stake
        cursor.execute(
            """INSERT INTO stakes (id, user_id, asset, amount, duration, apy, start_date, end_date, 
                estimated_reward, accrued_reward, status, auto_compound, last_reward_claim, days_remaining,
                early_withdrawal_penalty, metadata) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (stake_id, user_id, token, amount, duration, actual_apy, start_date, end_date, 
             round(estimated_reward, 6), 0.0, "active", auto_compound, start_date, duration,
             staking_option["early_withdrawal_penalty"],
             {
                 "token_name": supported_tokens[token]["name"],
                 "base_apy": base_apy,
                 "actual_apy": actual_apy,
                 "auto_compound": auto_compound,
                 "option_label": staking_option["label"]
             })
        )

        conn.commit()

        new_stake = {
            "id": stake_id,
            "userId": user_id,
            "asset": token,
            "amount": amount,
            "duration": duration,
            "apy": round(actual_apy, 2),
            "baseApy": base_apy,
            "startDate": start_date.isoformat(),
            "endDate": end_date.isoformat(),
            "estimatedReward": round(estimated_reward, 6),
            "accruedReward": 0.0,
            "status": "active",
            "autoCompound": auto_compound,
            "lastRewardClaim": start_date.isoformat(),
            "daysRemaining": duration,
            "earlyWithdrawalPenalty": staking_option["early_withdrawal_penalty"],
            "tokenName": supported_tokens[token]["name"]
        }

        return jsonify({
            "message": f"Staking de {token} iniciado com sucesso!",
            "stake": new_stake,
            "estimated_apy": f"{actual_apy:.2f}%",
            "estimated_rewards": f"{estimated_reward:.6f} {token}"
        }), 201

    except Exception as e:
        conn.rollback()
        print(f"[STAKING] Erro: {e}")
        return jsonify({"error": f"Erro ao registrar staking: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/unstake", methods=["POST"])
def unstake():
    """Retirar staking com penalidades claras"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    stake_id = data.get("stake_id")
    confirm_early_withdrawal = data.get("confirm_early_withdrawal", False)
    
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

        # ✅ USAR FUNÇÃO CORRIGIDA
        days_remaining = safe_days_remaining(stake["end_date"])
        
        is_early_withdrawal = days_remaining > 0
        penalty_rate = float(stake["early_withdrawal_penalty"]) if is_early_withdrawal else 0.0
        penalty_amount = float(stake["amount"]) * penalty_rate if is_early_withdrawal else 0.0
        
        return_amount = float(stake["amount"]) - penalty_amount
        accrued_reward = float(stake["accrued_reward"])

        if is_early_withdrawal and not confirm_early_withdrawal:
            return jsonify({
                "requires_confirmation": True,
                "warning": "RETIRADA ANTECIPADA DETECTADA",
                "penalty_rate": f"{penalty_rate * 100}%",
                "penalty_amount": penalty_amount,
                "original_amount": float(stake["amount"]),
                "return_amount": return_amount,
                "accrued_rewards": accrued_reward,
                "message": "Confirmação de retirada antecipada necessária."
            }), 400 # 400 para indicar que a requisição precisa de um parâmetro extra

        cursor.execute("BEGIN")

        # 1. Registrar no ledger (devolução do principal)
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, stake["asset"], return_amount, "unstake_principal", stake_id, 
             f"Retirada do principal do staking {stake_id} (Penalidade: {penalty_amount:.6f})")
        )

        # 2. Registrar no ledger (recompensa acumulada)
        if accrued_reward > 0:
            cursor.execute(
                "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, stake["asset"], accrued_reward, "unstake_reward", stake_id, 
                 f"Recompensa acumulada do staking {stake_id}")
            )

        # 3. Atualizar saldos (devolver principal + recompensa)
        total_return = return_amount + accrued_reward
        cursor.execute(
            "UPDATE balances SET available = available + %s, staking_balance = staking_balance - %s WHERE user_id = %s AND asset = %s",
            (total_return, stake["amount"], user_id, stake["asset"])
        )

        # 4. Atualizar registro de stake
        new_status = "withdrawn_early" if is_early_withdrawal else "withdrawn_mature"
        now = datetime.now(timezone.utc)
        cursor.execute(
            "UPDATE stakes SET status = %s, actual_return = %s, penalty_applied = %s, withdrawn_at = %s WHERE id = %s",
            (new_status, total_return, penalty_amount, now, stake_id)
        )

        conn.commit()

        return jsonify({
            "message": f"Staking {stake_id} retirado com sucesso.",
            "total_received": total_return,
            "returned_amount": return_amount,
            "accrued_rewards": accrued_reward,
            "penalty_applied": penalty_amount,
            "status": new_status
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"[UNSTAKE] Erro: {e}")
        return jsonify({"error": f"Erro ao retirar staking: {e}"}), 500
    finally:
        conn.close()

def update_stake_rewards(stake_id):
    """✅ CORREÇÃO: Função interna para calcular e atualizar recompensas de um stake"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM stakes WHERE id = %s AND status = 'active'", (stake_id,))
        stake = cursor.fetchone()
        
        if not stake:
            return False

        current_date = datetime.now(timezone.utc)
        
        # ✅ USAR FUNÇÃO CORRIGIDA
        time_since_last_claim = safe_datetime_diff(current_date, stake["last_reward_claim"])
        days_since_last_claim = time_since_last_claim.days

        if days_since_last_claim <= 0:
            return False # Nenhuma atualização necessária

        # 2. Calcular recompensa diária
        daily_rate = float(stake["apy"]) / 365 / 100
        
        if stake["auto_compound"]:
            # Se for compound, o montante base para o cálculo é o original + recompensas acumuladas
            base_amount = float(stake["amount"]) + float(stake["accrued_reward"])
            
            # Recálculo do montante total após 'days_since_last_claim' dias
            new_total_amount = base_amount * ((1 + daily_rate) ** days_since_last_claim)
            new_reward = new_total_amount - base_amount
        else:
            # Se não for compound, o montante base é apenas o original
            base_amount = float(stake["amount"])
            new_reward = base_amount * daily_rate * days_since_last_claim

        new_accrued_reward = float(stake["accrued_reward"]) + new_reward
        
        # ✅ USAR FUNÇÃO CORRIGIDA
        days_remaining = safe_days_remaining(stake["end_date"], current_date)

        # 4. Atualizar banco de dados
        cursor.execute(
            """UPDATE stakes 
            SET accrued_reward = %s, last_reward_claim = %s, days_remaining = %s, updated_at = %s
            WHERE id = %s""",
            (new_accrued_reward, current_date, days_remaining, current_date, stake_id)
        )
        
        conn.commit()
        return True

    except Exception as e:
        conn.rollback()
        print(f"[UPDATE REWARDS] Erro ao atualizar recompensas para {stake_id}: {e}")
        return False
    finally:
        conn.close()

@staking_bp.route("/claim-rewards", methods=["POST"])
def claim_rewards():
    """Coletar recompensas acumuladas"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    stake_id = data.get("stake_id")

    if not stake_id:
        return jsonify({"error": "ID do stake é obrigatório"}), 400

    # Garante que as recompensas estejam atualizadas antes de coletar
    update_stake_rewards(stake_id)
    
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM stakes WHERE id = %s AND user_id = %s", (stake_id, user_id))
        stake = cursor.fetchone()
        
        if not stake:
            return jsonify({"error": "Stake não encontrado"}), 404
        
        if stake["status"] != "active":
            return jsonify({"error": "Apenas stakes ativos podem coletar recompensas"}), 400

        reward_amount = float(stake["accrued_reward"])
        if reward_amount <= 0:
            return jsonify({"message": "Nenhuma recompensa acumulada para coletar."}), 200

        cursor.execute("BEGIN")

        # 1. Registrar no ledger (recompensa)
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, stake["asset"], reward_amount, "staking_reward", stake_id, 
             f"Coleta de recompensa de {reward_amount:.6f} {stake['asset']} do staking {stake_id}")
        )

        # 2. Atualizar saldos (adicionar à conta disponível)
        cursor.execute(
            "UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = %s",
            (reward_amount, user_id, stake["asset"])
        )

        # 3. Zerar recompensa acumulada no stake
        cursor.execute(
            "UPDATE stakes SET accrued_reward = 0.0, last_reward_claim = %s, updated_at = %s WHERE id = %s",
            (datetime.now(timezone.utc), datetime.now(timezone.utc), stake_id)
        )

        conn.commit()

        return jsonify({
            "message": f"Recompensa de {reward_amount:.6f} {stake['asset']} coletada com sucesso.",
            "amount_claimed": reward_amount
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"[CLAIM REWARDS] Erro: {e}")
        return jsonify({"error": f"Erro ao coletar recompensas: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/me", methods=["GET"])
def get_my_stakes():
    """✅ CORREÇÃO: Buscar todos os stakes ativos do usuário"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Atualizar recompensas de todos os stakes ativos antes de retornar
        cursor.execute("SELECT id FROM stakes WHERE user_id = %s AND status = 'active'", (user_id,))
        active_stakes = cursor.fetchall()
        
        for stake in active_stakes:
            try:
                update_stake_rewards(stake["id"])
            except Exception as e:
                print(f"⚠️ Erro ao atualizar stake {stake['id']}: {e}")
                continue

        # Buscar stakes atualizados
        cursor.execute("SELECT * FROM stakes WHERE user_id = %s", (user_id,))
        stakes = cursor.fetchall()
        
        # Formatar a saída
        formatted_stakes = []
        for stake in stakes:
            try:
                # ✅ USAR FUNÇÃO CORRIGIDA para calcular dias restantes
                days_remaining = safe_days_remaining(stake["end_date"])
                
                # ✅ GARANTIR que as datas sejam strings ISO formatadas corretamente
                start_date = stake["start_date"]
                end_date = stake["end_date"]
                last_reward_claim = stake["last_reward_claim"]
                
                # Se as datas são timezone-aware, converter para string ISO
                if hasattr(start_date, 'isoformat'):
                    start_date_iso = start_date.isoformat()
                else:
                    start_date_iso = start_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    
                if hasattr(end_date, 'isoformat'):
                    end_date_iso = end_date.isoformat()
                else:
                    end_date_iso = end_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    
                if hasattr(last_reward_claim, 'isoformat'):
                    last_reward_claim_iso = last_reward_claim.isoformat()
                else:
                    last_reward_claim_iso = last_reward_claim.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                
                formatted_stakes.append({
                    "id": stake["id"],
                    "userId": stake["user_id"],
                    "asset": stake["asset"],
                    "amount": float(stake["amount"]),
                    "duration": stake["duration"],
                    "apy": float(stake["apy"]),
                    "baseApy": stake["metadata"].get("base_apy", float(stake["apy"])),
                    "startDate": start_date_iso,
                    "endDate": end_date_iso,
                    "estimatedReward": float(stake["estimated_reward"]),
                    "accruedReward": float(stake["accrued_reward"]),
                    "status": stake["status"],
                    "autoCompound": stake["auto_compound"],
                    "lastRewardClaim": last_reward_claim_iso,
                    "daysRemaining": days_remaining,  # ✅ USAR VALOR CALCULADO CORRETAMENTE
                    "earlyWithdrawalPenalty": float(stake["early_withdrawal_penalty"]),
                    "tokenName": supported_tokens.get(stake["asset"], {}).get("name", stake["asset"])
                })
            except Exception as e:
                print(f"⚠️ Erro ao formatar stake {stake['id']}: {e}")
                continue

        return jsonify({"stakes": formatted_stakes}), 200
        
    except Exception as e:
        print(f"[GET MY STAKES] Erro: {e}")
        return jsonify({"error": f"Erro ao buscar stakes: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/options", methods=["GET"])
def get_staking_options():
    """Buscar opções de staking disponíveis"""
    return jsonify({
        "options": staking_options,
        "tokens": supported_tokens,
        "features": {
            "auto_compound": True,
            "multiple_tokens": True,
            "early_withdrawal": True,
            "competitive_apy": True
        }
    }), 200

@staking_bp.route("/stats", methods=["GET"])
def get_staking_stats():
    """Estatísticas de staking do usuário"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Atualizar recompensas de todos os stakes ativos primeiro
        cursor.execute("SELECT id FROM stakes WHERE user_id = %s AND status = 'active'", (user_id,))
        active_stakes = cursor.fetchall()
        
        for stake in active_stakes:
            try:
                update_stake_rewards(stake["id"])
            except Exception as e:
                print(f"⚠️ Erro ao atualizar stake {stake['id']}: {e}")
                continue
        
        # Total em staking por token
        cursor.execute('''
            SELECT asset, SUM(amount) as total_staked, SUM(accrued_reward) as total_rewards
            FROM stakes 
            WHERE user_id = %s AND status = 'active'
            GROUP BY asset
        ''', (user_id,))
        asset_stats = cursor.fetchall()
        
        # Estatísticas gerais
        cursor.execute('''
            SELECT 
                COUNT(*) as total_stakes,
                SUM(amount) as total_amount,
                SUM(accrued_reward) as total_accrued_rewards,
                AVG(apy) as average_apy
            FROM stakes 
            WHERE user_id = %s AND status = 'active'
        ''', (user_id,))
        general_stats = cursor.fetchone()
        
        stats = {
            "asset_breakdown": [
                {
                    "asset": stat["asset"],
                    "total_staked": float(stat["total_staked"]),
                    "total_rewards": float(stat["total_rewards"]),
                    "token_name": supported_tokens.get(stat["asset"], {}).get("name", stat["asset"])
                }
                for stat in asset_stats
            ],
            "general": {
                "total_stakes": general_stats["total_stakes"] or 0,
                "total_amount": float(general_stats["total_amount"] or 0),
                "total_accrued_rewards": float(general_stats["total_accrued_rewards"] or 0),
                "average_apy": float(general_stats["average_apy"] or 0)
            },
            "reward_history": []  # Simplificado por enquanto
        }
        
        return jsonify({"stats": stats}), 200
        
    except Exception as e:
        print(f"[STATS] Erro: {e}")
        return jsonify({"error": f"Erro ao buscar estatísticas: {e}"}), 500
    finally:
        conn.close()

@staking_bp.route("/auto-compound/<stake_id>", methods=["PUT"])
def toggle_auto_compound(stake_id):
    """Ativar/desativar compound automático"""
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Usuário não autenticado"}), 401
    
    data = request.get_json()
    auto_compound = data.get("auto_compound", False)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE stakes SET auto_compound = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s AND user_id = %s",
            (auto_compound, stake_id, user_id)
        )
        
        if cursor.rowcount == 0:
            return jsonify({"error": "Stake não encontrado"}), 404
            
        conn.commit()
        
        return jsonify({
            "message": f"Compound automático {'ativado' if auto_compound else 'desativado'} com sucesso",
            "auto_compound": auto_compound
        }), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Erro ao atualizar compound automático: {e}"}), 500
    finally:
        conn.close()
