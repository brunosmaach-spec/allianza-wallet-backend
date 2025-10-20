from backend_wallet_integration import app
import os

# Configurar variáveis de ambiente (Render vai substituir)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)