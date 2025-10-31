import sqlite3
from datetime import datetime, timezone
import os

DATABASE_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'allianza_wallet.db')

def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tabela de usuários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nickname TEXT,
            wallet_address TEXT UNIQUE,
            private_key TEXT,
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
            staking_plan TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            status TEXT DEFAULT 'active' NOT NULL,
            last_reward_claim TEXT,
            total_rewards_claimed REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')

    # Tabela de compras do site
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS site_purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            amount REAL NOT NULL,
            method TEXT NOT NULL,
            source_name TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # Tabela de pagamentos diretos com cripto (NOVA)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS direct_crypto_payments (
            payment_id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            amount_brl REAL NOT NULL,
            currency TEXT NOT NULL,
            required_amount REAL NOT NULL,
            master_wallet TEXT NOT NULL,
            network TEXT NOT NULL,
            description TEXT,
            qr_data TEXT,
            qr_code_base64 TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            confirmed_at TEXT,
            tx_hash TEXT
        );
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Banco de dados inicializado com sucesso.")
