from flask import Blueprint, request, jsonify, g
from datetime import datetime, timedelta
import uuid
from database_neon import get_db_connection

# Simulação de banco de dados
# Em um ambiente real, isso seria um ORM como SQLAlchemy com um banco de dados real (PostgreSQL, MySQL, etc.)
# Para simplificar, usaremos um dicionário em memória.

# Estrutura de dados para usuários (simplificada)
# users = {
#     "user_id_1": {"id": "user_id_1", "balance": 1000, "email": "test@example.com"}
# }

# Estrutura de dados para stakes
# stakes = {
#     "stake_id_1": {"id": "stake_id_1", "userId": "user_id_1", "amount": 100, ...}
# }

# Usaremos um objeto global para simular o banco de dados para que possa ser acessado por diferentes chamadas
# No Flask, 'g' é um objeto global para a requisição atual, mas para simular persistência entre requisições,
# usaremos um dicionário simples.

# Simulação de banco de dados em memória (para fins de demonstração)
# Em um ambiente real, isso seria um banco de dados persistente.
# Opções de staking com APYs ousados
staking_options = [
    {"duration": 30, "apy": 120.0, "label": "30 dias", "multiplier": 1.0},
    {"duration": 90, "apy": 180.0, "label": "90 dias", "multiplier": 1.2},
    {"duration": 180, "apy": 250.0, "label": "180 dias", "multiplier": 1.5},
    {"duration": 365, "apy": 400.0, "label": "1 ano", "multiplier": 2.0}
]

staking_bp = Blueprint("staking", __name__)

def get_user_id_from_token():
    # Em um ambiente real, isso envolveria decodificação JWT
    # Para integração com backend_wallet_integration.py, assumimos que request.user_id já foi definido
    from flask import request
    return request.user_id

def get_user_balance(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT available FROM balances WHERE user_id = %s AND asset = 'ALZ'", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result['available'] if result else 0.0

def update_user_balance(user_id, amount):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE balances SET available = available + %s WHERE user_id = %s AND asset = 'ALZ'", (amount, user_id))
    conn.commit()
    conn.close()
    return get_user_balance(user_id)


def calculate_rewards(amount, duration, apy, auto_compound=False):
    # Simplificação: APY é anual, dividimos por 365 para obter a taxa diária
    daily_rate = apy / 365 / 100
    if auto_compound:
        # Para simplificar, vamos usar um cálculo de juros compostos diário
        # Em um sistema real, a frequência de composição pode variar
        total_amount = amount * ((1 + daily_rate) ** duration)
        return total_amount - amount
    else:
        return amount * daily_rate * duration

@staking_bp.route("/stake", methods=["POST"])
def stake():
    user_id = get_user_id_from_token() # Obter user_id do token de autenticação
    data = request.get_json()
    amount = float(data.get("amount"))
    duration = int(data.get("duration"))
    apy = float(data.get("apy"))
    auto_compound = data.get("auto_compound", False)

    print(f"[STAKING] Requisição de staking recebida para user_id: {user_id}")
    print(f"[STAKING] Dados recebidos: {data}")
    print(f"[STAKING] Dados da requisição: amount={amount}, duration={duration}, apy={apy}, auto_compound={auto_compound}")

    if amount <= 0:
        print("[STAKING] Erro: Valor de staking deve ser positivo.")
        return jsonify({"error": "Valor de staking deve ser positivo."}), 400

    user_balance = get_user_balance(user_id)
    print(f"[STAKING] Saldo atual do usuário {user_id}: {user_balance}")
    if user_balance < amount:
        print(f"[STAKING] Erro: Saldo insuficiente para staking. Saldo: {user_balance}, Tentativa de staking: {amount}")
        return jsonify({"error": "Saldo insuficiente para staking."}), 400

    # Debitar valor da carteira do usuário (isso será feito na transação do banco de dados)
    # update_user_balance(user_id, -amount) # Removido pois será tratado na transação

    stake_id = str(uuid.uuid4())
    start_date = datetime.now()
    end_date = start_date + timedelta(days=duration)
    estimated_reward = calculate_rewards(amount, duration, apy, auto_compound)
    print(f"[STAKING] Novo stake_id: {stake_id}, start_date: {start_date}, end_date: {end_date}, estimated_reward: {estimated_reward}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        conn.execute("BEGIN TRANSACTION")

        # Registrar entrada no ledger para o staking
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, "ALZ", -amount, "stake", stake_id, f"Staking de {amount} ALZ por {duration} dias")
        )
        print(f"[STAKING] Registrado no ledger: -{amount} ALZ para user {user_id} (stake)")

        # Atualizar saldo bloqueado e staking_balance na tabela de balances
        cursor.execute(
            "UPDATE balances SET available = available - %s, staking_balance = staking_balance + %s WHERE user_id = %s AND asset = 'ALZ'",
            (amount, amount, user_id)
        )
        print(f"[STAKING] Saldo do usuário {user_id} atualizado: available -= {amount}, staking_balance += {amount}")

        # Inserir o novo stake na tabela de stakes
        cursor.execute(
            "INSERT INTO stakes (id, user_id, amount, duration, apy, start_date, end_date, estimated_reward, accrued_reward, status, auto_compound, last_reward_claim, days_remaining) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (stake_id, user_id, amount, duration, apy, start_date.isoformat(), end_date.isoformat(), round(estimated_reward, 6), 0.0, "active", auto_compound, start_date.isoformat(), duration)
        )
        print(f"[STAKING] Novo stake inserido na tabela stakes: {stake_id}")
        conn.commit()
        print("[STAKING] Transação de staking comitada com sucesso.")

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
    except Exception as e:
        conn.rollback()
        print(f"[STAKING] Erro na transação de staking, rollback: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erro ao registrar staking: {e}"}), 500
    finally:
        conn.close()
        print("[STAKING] Conexão com o banco de dados fechada.")

    return jsonify({"message": "Staking iniciado com sucesso!", "stake": new_stake}), 201

@staking_bp.route("/unstake", methods=["POST"])
def unstake():
    user_id = get_user_id_from_token()
    print("[UNSTAKE] Requisição de unstake recebida - request.get_json():", request.get_json())
    data = request.get_json()
    stake_id = data.get("stake_id")
    print(f"[UNSTAKE] Requisição de unstake recebida para user_id: {user_id}, stake_id: {stake_id}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM stakes WHERE id = %s AND user_id = %s", (stake_id, user_id))
        stake = cursor.fetchone()
        print(f"[UNSTAKE] Stake encontrado: {stake}")

        if not stake:
            print("[UNSTAKE] Erro: Staking não encontrado ou não pertence ao usuário.")
            return jsonify({"error": "Staking não encontrado ou não pertence ao usuário."}), 404
        if stake["status"] != "active":
            print("[UNSTAKE] Erro: Staking não está ativo.")
            return jsonify({"error": "Staking não está ativo."}), 400

        start_date = datetime.fromisoformat(stake["start_date"])
        end_date = datetime.fromisoformat(stake["end_date"])
        now = datetime.now()
        days_remaining = max(0, (end_date - now).days)
        print(f"[UNSTAKE] Dias restantes para o stake: {days_remaining}")

        return_amount = stake["amount"]
        penalty = 0
        if days_remaining > 0:
            penalty = stake["amount"] * 0.05 # 5% de penalidade por retirada antecipada
            return_amount -= penalty
        print(f"[UNSTAKE] Valor a ser retornado: {return_amount}, Penalidade: {penalty}")

        conn.execute("BEGIN TRANSACTION")

        # Registrar entrada no ledger para o unstaking
        orig_amount = stake["amount"]
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, "ALZ", return_amount + stake["accrued_reward"], "unstake", stake_id,
             f"Unstaking de {orig_amount} ALZ (retorno: {return_amount}, penalidade: {penalty})")
        )
        print(f"[UNSTAKE] Registrado no ledger: {return_amount + stake['accrued_reward']} ALZ para user {user_id} (unstake)")

        # Atualizar saldo disponível e staking_balance
        cursor.execute(
            "UPDATE balances SET available = available + %s, staking_balance = staking_balance - %s WHERE user_id = %s AND asset = 'ALZ'",
            (return_amount + stake["accrued_reward"], stake["amount"], user_id)
        )
        print(f"[UNSTAKE] Saldo do usuário {user_id} atualizado: available += {return_amount + stake['accrued_reward']}, staking_balance -= {stake['amount']}")

        # Atualizar status do stake
        cursor.execute("UPDATE stakes SET status = %s, accrued_reward = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", ("withdrawn", 0, stake_id))
        print(f"[UNSTAKE] Status do stake {stake_id} atualizado para 'withdrawn'.")
        conn.commit()
        print("[UNSTAKE] Transação de unstake comitada com sucesso.")

    except Exception as e:
        conn.rollback()
        print(f"[UNSTAKE] Erro na transação de unstake, rollback: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erro ao retirar staking: {e}"}), 500
    finally:
        conn.close()
        print("[UNSTAKE] Conexão com o banco de dados fechada.")

    return jsonify({"message": "Staking retirado com sucesso!", "returned_amount": return_amount, "penalty": penalty}), 200

@staking_bp.route("/claim-rewards", methods=["POST"])
def claim_rewards():
    user_id = get_user_id_from_token()
    data = request.get_json()
    stake_id = data.get("stake_id")
    print(f"[CLAIM_REWARDS] Requisição de claim rewards recebida para user_id: {user_id}, stake_id: {stake_id}")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM stakes WHERE id = %s AND user_id = %s", (stake_id, user_id))
        stake = cursor.fetchone()
        print(f"[CLAIM_REWARDS] Stake encontrado: {stake}")

        if not stake:
            print("[CLAIM_REWARDS] Erro: Staking não encontrado ou não pertence ao usuário.")
            return jsonify({"error": "Staking não encontrado ou não pertence ao usuário."}), 404
        if stake["status"] != "active":
            print("[CLAIM_REWARDS] Erro: Staking não está ativo.")
            return jsonify({"error": "Staking não está ativo."}), 400
        if stake["accrued_reward"] <= 0:
            print("[CLAIM_REWARDS] Nenhuma recompensa para coletar.")
            return jsonify({"message": "Nenhuma recompensa para coletar."}), 200

        rewards_to_claim = stake["accrued_reward"]
        print(f"[CLAIM_REWARDS] Recompensas a coletar: {rewards_to_claim}")

        conn.execute("BEGIN TRANSACTION")

        # Registrar entrada no ledger para a reivindicação de recompensas
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, related_id, description) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, "ALZ", rewards_to_claim, "claim_reward", stake_id, f"Recompensa de staking coletada: {rewards_to_claim} ALZ")
        )
        print(f"[CLAIM_REWARDS] Registrado no ledger: {rewards_to_claim} ALZ para user {user_id} (claim_reward)")

        # Creditar recompensas na carteira do usuário (saldo disponível)
        cursor.execute(
               "UPDATE balances SET available = available + %s, staking_balance = staking_balance - %s WHERE user_id = %s AND asset = 'ALZ'",
            (rewards_to_claim, rewards_to_claim, user_id)
        )
        print(f"[CLAIM_REWARDS] Saldo do usuário {user_id} atualizado: available += {rewards_to_claim}, staking_balance -= {rewards_to_claim}")

        # Atualizar o stake no banco de dados
        cursor.execute("UPDATE stakes SET accrued_reward = %s, last_reward_claim = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (0, datetime.now().isoformat(), stake_id))
        print(f"[CLAIM_REWARDS] Stake {stake_id} atualizado: accrued_reward = 0, last_reward_claim = {datetime.now().isoformat()}")
        conn.commit()
        print("[CLAIM_REWARDS] Transação de claim rewards comitada com sucesso.")

    except Exception as e:
        conn.rollback()
        print(f"[CLAIM_REWARDS] Erro na transação de claim rewards, rollback: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erro ao coletar recompensas: {e}"}), 500
    finally:
        conn.close()
        print("[CLAIM_REWARDS] Conexão com o banco de dados fechada.")

    return jsonify({"message": "Recompensas coletadas com sucesso!", "claimed_amount": rewards_to_claim}), 200

@staking_bp.route("/me", methods=["GET"])
def get_my_stakes():
    user_id = get_user_id_from_token()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM stakes WHERE user_id = %s AND status = %s", (user_id, "active"))
    user_stakes_db = cursor.fetchall()
    conn.close()

    user_stakes = []
    for stake_db in user_stakes_db:
        stake = dict(stake_db)
        # Convertendo chaves para camelCase para compatibilidade com o frontend
        stake["userId"] = stake.pop("user_id")
        stake["startDate"] = stake.pop("start_date")
        stake["endDate"] = stake.pop("end_date")
        stake["estimatedReward"] = stake.pop("estimated_reward")
        stake["accruedReward"] = stake.pop("accrued_reward")
        stake["autoCompound"] = stake.pop("auto_compound")
        stake["lastRewardClaim"] = stake.pop("last_reward_claim")
        stake["daysRemaining"] = stake.pop("days_remaining")
        user_stakes.append(stake)


    # Atualizar dinamicamente accruedReward e daysRemaining para simulação
    for stake in user_stakes:
        start_date = datetime.fromisoformat(stake["startDate"])
        end_date = datetime.fromisoformat(stake["endDate"])
        last_claim_date = datetime.fromisoformat(stake["lastRewardClaim"])
        
        now = datetime.now()
        
        # Calcular dias restantes
        stake["daysRemaining"] = max(0, (end_date - now).days)

        # Calcular recompensas acumuladas desde o último claim
        days_since_last_claim = (now - datetime.fromisoformat(stake["lastRewardClaim"])).days
        if days_since_last_claim > 0:
            # Apenas acumular recompensas para o período ativo
            days_to_accrue = min(days_since_last_claim, (end_date - datetime.fromisoformat(stake["lastRewardClaim"])).days)
            if days_to_accrue > 0:
                accrued_since_last = calculate_rewards(stake["amount"], days_to_accrue, stake["apy"], stake["autoCompound"])
                stake["accruedReward"] = round(stake["accruedReward"] + accrued_since_last, 6)
                # Atualiza o lastRewardClaim no banco de dados
                conn_update = get_db_connection()
                cursor_update = conn_update.cursor()
                cursor_update.execute("UPDATE stakes SET accrued_reward = %s, last_reward_claim = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (stake["accruedReward"], now.isoformat(), stake["id"]))
                conn_update.commit()
                conn_update.close()
                stake["lastRewardClaim"] = now.isoformat()
    return jsonify({"stakes": user_stakes}), 200

@staking_bp.route("/options", methods=["GET"])
def get_staking_options():
    return jsonify({"options": staking_options}), 200

@staking_bp.route("/history", methods=["GET"])
def get_staking_history():
    user_id = get_user_id_from_token()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM ledger_entries WHERE user_id = %s AND entry_type IN ('stake', 'unstake', 'stake_reward') ORDER BY created_at DESC",
            (user_id,)
        )
        history = cursor.fetchall()
        return jsonify({"history": [dict(row) for row in history]}), 200
    except Exception as e:
        return jsonify({"error": f"Erro ao obter histórico de staking: {e}"}), 500
    finally:
        conn.close()

# Exemplo de como registrar o blueprint em um aplicativo Flask principal:
# from flask import Flask
# app = Flask(__name__)
# app.register_blueprint(staking_bp, url_prefix="/staking")

# Para testar este arquivo isoladamente (executar como script Python):
if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    app.register_blueprint(staking_bp, url_prefix="/staking")

    @app.route("/", methods=["GET"])
    def index():
        return "Backend de Staking Allianza funcionando!"

    # Endpoint para simular login e obter user_id (para testes)
    @app.route("/login_test", methods=["POST"])
    def login_test():
        # Em um app real, isso seria um login de verdade
        # Aqui, apenas configuramos um user_id para o contexto de teste
        return jsonify({"message": "Logged in as test_user_id", "user_id": "test_user_id"})

    # Endpoint para verificar o saldo do usuário de teste
    @app.route("/balance_test", methods=["GET"])
    def balance_test():
        user_id = get_user_id_from_token()
        balance = get_user_balance(user_id)
        return jsonify({"user_id": user_id, "balance": balance})

    app.run(debug=True, port=5000)
