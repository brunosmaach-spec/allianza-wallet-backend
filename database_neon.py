import os
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()

class NeonDatabase:
    def __init__(self):
        self.database_url = os.getenv('NEON_DATABASE_URL')
        if self.database_url:
            safe_url = self.database_url.split('@')
            if len(safe_url) > 1:
                print(f"🔗 Conectando ao: {safe_url[1].split('?')[0]}")
            else:
                print("🔗 URL do Neon configurada")
        else:
            print("❌ NEON_DATABASE_URL não encontrada")
        
    def get_connection(self):
        """Obter conexão com o Neon PostgreSQL"""
        if not self.database_url:
            raise ValueError("NEON_DATABASE_URL não configurada no .env")
        
        try:
            conn = psycopg.connect(
                self.database_url,
                row_factory=dict_row,
                connect_timeout=10
            )
            return conn
        except Exception as e:
            print(f"❌ Erro de conexão com Neon: {e}")
            raise

    def init_db(self):
        """Inicializar tabelas no Neon"""
        conn = None
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            print("🗃️  Criando/verificando tabelas no Neon...")
            
            # Tabela de usuários
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password TEXT,
                    nickname VARCHAR(100),
                    wallet_address VARCHAR(255) UNIQUE,
                    private_key TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            print("✅ Tabela 'users' criada/verificada")
            
            # Tabela de saldos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS balances (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    asset VARCHAR(10) DEFAULT 'ALZ' NOT NULL,
                    available NUMERIC(20,8) DEFAULT 0.0 NOT NULL,
                    locked NUMERIC(20,8) DEFAULT 0.0 NOT NULL,
                    staking_balance NUMERIC(20,8) DEFAULT 0.0 NOT NULL,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            print("✅ Tabela 'balances' criada/verificada")
            
            # Tabela de ledger
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    asset VARCHAR(10) DEFAULT 'ALZ' NOT NULL,
                    amount NUMERIC(20,8) NOT NULL,
                    entry_type VARCHAR(50) NOT NULL,
                    related_id VARCHAR(100),
                    description TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    idempotency_key VARCHAR(255) UNIQUE
                );
            ''')
            print("✅ Tabela 'ledger_entries' criada/verificada")
            
            # Tabela de solicitações de saque
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS withdrawal_requests (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    to_address VARCHAR(255) NOT NULL,
                    amount NUMERIC(20,8) NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
                    tx_hash VARCHAR(255),
                    gas_used NUMERIC(20,8),
                    gas_cost_matic NUMERIC(20,8),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            print("✅ Tabela 'withdrawal_requests' criada/verificada")
            
            # Tabela de stakes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS stakes (
                    id VARCHAR(100) PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    amount NUMERIC(20,8) NOT NULL,
                    duration INTEGER NOT NULL,
                    apy NUMERIC(5,2) NOT NULL,
                    start_date TIMESTAMPTZ NOT NULL,
                    end_date TIMESTAMPTZ NOT NULL,
                    estimated_reward NUMERIC(20,8) NOT NULL,
                    accrued_reward NUMERIC(20,8) DEFAULT 0.0 NOT NULL,
                    status VARCHAR(20) DEFAULT 'active' NOT NULL,
                    auto_compound BOOLEAN DEFAULT FALSE NOT NULL,
                    last_reward_claim TIMESTAMPTZ NOT NULL,
                    days_remaining INTEGER NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            print("✅ Tabela 'stakes' criada/verificada")

            # Tabela de pagamentos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS payments (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    amount NUMERIC(20,8) NOT NULL,
                    method VARCHAR(50) NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
                    tx_hash VARCHAR(255),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMPTZ,
                    metadata JSONB,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
                );
            ''')
            print("✅ Tabela 'payments' criada/verificada")

            # Tabela de logs administrativos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_logs (
                    id SERIAL PRIMARY KEY,
                    admin_user VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    description TEXT,
                    target_id INTEGER,
                    ip_address VARCHAR(45),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            print("✅ Tabela 'admin_logs' criada/verificada")
            
            # Índices para performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ledger_user_id ON ledger_entries(user_id);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ledger_created_at ON ledger_entries(created_at);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_stakes_user_id ON stakes(user_id);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_stakes_status ON stakes(status);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payments_email ON payments(email);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_logs_admin_user ON admin_logs(admin_user);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_logs_created_at ON admin_logs(created_at);')
            print("✅ Índices criados/verificados")
            
            conn.commit()
            print("🎉 Todas as tabelas foram criadas/verificadas com sucesso no Neon!")
            
        except Exception as e:
            if conn:
                conn.rollback()
            print(f"❌ Erro ao criar tabelas: {e}")
            raise
        finally:
            if conn:
                conn.close()

# Instância global
neon_db = NeonDatabase()

# Funções de conveniência
def get_db_connection():
    return neon_db.get_connection()

def init_db():
    return neon_db.init_db()
