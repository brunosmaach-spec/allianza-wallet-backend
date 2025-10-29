# direct_crypto_service.py - SISTEMA DE PAGAMENTO DIRETO SEM INTERMEDIÁRIOS
import os
import json
import secrets
from datetime import datetime, timedelta
from decimal import Decimal

class DirectCryptoPaymentService:
    def __init__(self):
        # SUAS WALLETS MASTER PARA RECEBIMENTO DIRETO
        self.master_wallets = {
            'USDT': {
                'polygon': '0x48Ec8b17B7af735AB329fA07075247FAf3a09599',
                'ethereum': '0xAFE6826B11651014171D7c97c1C38d5514d9B217',
                'network': 'Polygon/ERC-20'
            },
            'MATIC': {
                'polygon': '0x48Ec8b17B7af735AB329fA07075247FAf3a09599',
                'network': 'Polygon'
            },
            'ETH': {
                'ethereum': '0xAFE6826B11651014171D7c97c1C38d5514d9B217',
                'network': 'Ethereum'
            }
        }
        
        # Taxas de câmbio aproximadas (em BRL)
        self.exchange_rates = {
            'USDT': 5.50,  # 1 USDT ≈ R$ 5,50
            'MATIC': 4.20, # 1 MATIC ≈ R$ 4,20  
            'ETH': 18000.00 # 1 ETH ≈ R$ 18.000,00
        }
        
        # Pagamentos ativos
        self.active_payments = {}
        
    def create_direct_payment(self, email, amount_brl, currency='USDT'):
        """Criar um pagamento direto para sua wallet"""
        try:
            amount_brl = float(amount_brl)
            
            if currency not in self.master_wallets:
                return {"success": False, "error": f"Moeda {currency} não suportada"}
            
            # Calcular quantidade necessária na moeda escolhida
            required_amount = amount_brl / self.exchange_rates[currency]
            
            # Gerar ID único para o pagamento
            payment_id = f"direct_{secrets.token_hex(8)}"
            
            # Criar dados do pagamento
            payment_data = {
                'payment_id': payment_id,
                'email': email,
                'amount_brl': amount_brl,
                'currency': currency,
                'required_amount': round(required_amount, 6),
                'master_wallet': self.master_wallets[currency].get('polygon') or self.master_wallets[currency].get('ethereum'),
                'network': self.master_wallets[currency]['network'],
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
                'status': 'pending'
            }
            
            # Armazenar pagamento
            self.active_payments[payment_id] = payment_data
            
            print(f"💰 PAGAMENTO DIRETO CRIADO: {payment_id}")
            print(f"   Email: {email}")
            print(f"   Valor: R$ {amount_brl} → {required_amount} {currency}")
            print(f"   Wallet: {payment_data['master_wallet']}")
            print(f"   Rede: {payment_data['network']}")
            
            return {
                "success": True,
                "payment_id": payment_id,
                "payment_data": payment_data
            }
            
        except Exception as e:
            print(f"❌ Erro ao criar pagamento direto: {e}")
            return {"success": False, "error": str(e)}
    
    def get_payment_status(self, payment_id):
        """Obter status de um pagamento (simulação - em produção você verificaria a blockchain)"""
        if payment_id not in self.active_payments:
            return {"success": False, "error": "Pagamento não encontrado"}
        
        payment = self.active_payments[payment_id]
        
        # Simulação: Em produção, você verificaria se o pagamento foi recebido
        # na blockchain usando web3.py ou APIs de explorador de blocos
        
        # Por enquanto, retornamos status pendente
        # Em produção, você implementaria a verificação real aqui
        return {
            "success": True,
            "payment_status": payment,
            "verified": False,  # Em produção, seria True se o pagamento for confirmado
            "confirmation_note": "⚠️ Sistema em desenvolvimento - Pagamentos serão verificados manualmente"
        }
    
    def verify_payment_manual(self, payment_id, tx_hash):
        """Verificar manualmente um pagamento (para uso administrativo)"""
        if payment_id not in self.active_payments:
            return {"success": False, "error": "Pagamento não encontrado"}
        
        payment = self.active_payments[payment_id]
        payment['status'] = 'completed'
        payment['tx_hash'] = tx_hash
        payment['verified_at'] = datetime.utcnow().isoformat()
        
        print(f"✅ PAGAMENTO VERIFICADO MANUALMENTE: {payment_id}")
        print(f"   TX Hash: {tx_hash}")
        
        return {
            "success": True,
            "message": "Pagamento verificado com sucesso",
            "payment": payment
        }
    
    def get_supported_currencies(self):
        """Obter moedas suportadas"""
        return {
            "success": True,
            "currencies": [
                {
                    "symbol": "USDT",
                    "name": "Tether USD",
                    "networks": ["Polygon", "Ethereum"],
                    "min_amount_brl": 5.50,
                    "exchange_rate": self.exchange_rates['USDT']
                },
                {
                    "symbol": "MATIC", 
                    "name": "Polygon",
                    "networks": ["Polygon"],
                    "min_amount_brl": 5.50,
                    "exchange_rate": self.exchange_rates['MATIC']
                },
                {
                    "symbol": "ETH",
                    "name": "Ethereum",
                    "networks": ["Ethereum"], 
                    "min_amount_brl": 50.00,
                    "exchange_rate": self.exchange_rates['ETH']
                }
            ],
            "bonus_note": "🎁 Todos os pagamentos em cripto recebem +2% de bônus em ALZ!"
        }

# Instância global do serviço
direct_crypto_service = DirectCryptoPaymentService()