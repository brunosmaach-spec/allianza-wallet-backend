import sqlite3
import sys

DATABASE_NAME = 'allianza_wallet.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def add_balance_to_user(user_id, amount, asset, db_name):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Inserir ou atualizar o saldo
        cursor.execute(
            "INSERT OR REPLACE INTO balances (user_id, asset, available, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            (user_id, asset, amount)
        )
        conn.commit()
        print(f"Saldo de {amount} {asset} adicionado/atualizado para o usuário ID {user_id} com sucesso.")

        # Opcional: Adicionar entrada no ledger para registro
        cursor.execute(
            "INSERT INTO ledger_entries (user_id, asset, amount, entry_type, description, created_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (user_id, asset, amount, 'deposit', 'Saldo inicial para teste')
        )
        conn.commit()
        print(f"Entrada no ledger registrada para o usuário ID {user_id}.")

    except sqlite3.Error as e:
        print(f"Erro ao acessar o banco de dados: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: python3.11 add_balance.py <user_id> <amount>")
        sys.exit(1)

    user_id = int(sys.argv[1])
    amount = float(sys.argv[2])
    asset = 'ALZ'

    add_balance_to_user(user_id, amount, asset, DATABASE_NAME)

