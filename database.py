import sqlite3

import os
DATABASE_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'allianza_wallet.db')

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row # Permite acessar colunas por nome
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tabela de usuários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, -- Em produção, use hash de senha
            nickname TEXT,
            wallet_address TEXT UNIQUE, -- Endereço da carteira Allianza (ÚNICO para cada usuário)
            private_key TEXT, -- Chave privada da carteira gerada internamente
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # Tabela de saldos internos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS balances (
            user_id INTEGER PRIMARY KEY,
            asset TEXT DEFAULT 'ALZ' NOT NULL,
            available REAL DEFAULT 0.0 NOT NULL,
            locked REAL DEFAULT 0.0 NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')


    # Tabela de ledger imutável
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ledger_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            asset TEXT DEFAULT 'ALZ' NOT NULL,
            amount REAL NOT NULL,
            entry_type TEXT NOT NULL,
            related_id TEXT,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            idempotency_key TEXT UNIQUE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')


    # Tabela de solicitações de saque
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS withdrawal_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            to_address TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending' NOT NULL,
            tx_hash TEXT,
            gas_used REAL,
            gas_cost_matic REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')

    # Tabela de stakes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stakes (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            duration INTEGER NOT NULL,
            apy REAL NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            estimated_reward REAL NOT NULL,
            accrued_reward REAL DEFAULT 0.0 NOT NULL,
            status TEXT DEFAULT 'active' NOT NULL,
            auto_compound BOOLEAN DEFAULT FALSE NOT NULL,
            last_reward_claim TEXT NOT NULL,
            days_remaining INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Banco de dados inicializado com sucesso.")

