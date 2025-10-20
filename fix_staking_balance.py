import sqlite3
import os

# Caminho do banco de dados
DATABASE_NAME = '/home/ubuntu/upload/allianza_wallet.db'

def fix_staking_balance():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Obter todos os usuários
        cursor.execute("SELECT user_id FROM balances WHERE asset = 'ALZ'")
        users = cursor.fetchall()
        
        for user in users:
            user_id = user['user_id']
            
            # Calcular o total de stakes ativos para este usuário
            cursor.execute("SELECT SUM(amount) as total_staked FROM stakes WHERE user_id = ? AND status = 'active'", (user_id,))
            result = cursor.fetchone()
            total_staked = result['total_staked'] if result['total_staked'] else 0.0
            
            # Atualizar staking_balance para refletir o total de stakes ativos
            cursor.execute("UPDATE balances SET staking_balance = ? WHERE user_id = ? AND asset = 'ALZ'", (total_staked, user_id))
            
            print(f"User {user_id}: staking_balance atualizado para {total_staked} ALZ")
        
        conn.commit()
        print("\nSincronização concluída com sucesso!")
        
    except Exception as e:
        conn.rollback()
        print(f"Erro ao sincronizar staking_balance: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    fix_staking_balance()
