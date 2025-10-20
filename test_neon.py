#!/usr/bin/env python3
"""
Script para testar conexão com o Neon
"""
import os
from dotenv import load_dotenv

load_dotenv()

def test_neon_connection():
    print("🧪 Testando conexão com Neon...")
    
    # Verificar se .env existe
    if not os.path.exists('.env'):
        print("❌ Arquivo .env não encontrado")
        return False
    
    # Verificar variáveis
    neon_url = os.getenv('NEON_DATABASE_URL')
    if not neon_url:
        print("❌ NEON_DATABASE_URL não configurada no .env")
        return False
    
    # Mostrar URL de forma segura
    safe_url = neon_url.split('@')
    if len(safe_url) > 1:
        print(f"📋 Conectando em: {safe_url[1].split('?')[0]}")
    else:
        print("📋 URL configurada")
    
    # Tentar importar e conectar
    try:
        from database_neon import neon_db
        conn = neon_db.get_connection()
        
        # Testar consulta simples
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        print(f"✅ PostgreSQL version: {version['version']}")
        
        # Testar se podemos criar tabelas
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            LIMIT 5;
        """)
        tables = cursor.fetchall()
        print(f"📊 Tables no banco: {len(tables)} encontradas")
        
        cursor.close()
        conn.close()
        print("🎉 Conexão com Neon funcionando perfeitamente!")
        return True
        
    except Exception as e:
        print(f"❌ Erro na conexão: {e}")
        return False

if __name__ == "__main__":
    test_neon_connection()