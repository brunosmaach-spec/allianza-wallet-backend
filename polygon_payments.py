# payments/polygon_payments.py
import os
import json
import asyncio
from web3 import Web3
from web3.middleware import geth_poa_middleware
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

class PolygonPaymentProcessor:
    def __init__(self):
        self.network_name = "Polygon"
        self.chain_id = 137  # Polygon Mainnet
        self.rpc_url = os.getenv('POLYGON_RPC_URL', 'https://polygon-rpc.com')
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        # Adicionar middleware para redes POA
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        # Wallet mestre da Allianza (apenas para recebimentos)
        self.master_wallet = os.getenv('POLYGON_MASTER_WALLET')
        self.private_key = os.getenv('POLYGON_MASTER_PRIVATE_KEY')
        
        # Contratos conhecidos
        self.usdt_contract_address = Web3.to_checksum_address('0xc2132D05D31c914a87C6611C10748AEb04B58e8F')
        self.alz_contract_address = Web3.to_checksum_address(os.getenv('ALZ_CONTRACT_POLYGON', ''))
        
        # ABI dos contratos
        self.erc20_abi = [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "symbol",
                "outputs": [{"name": "", "type": "string"}],
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "to", "type": "address"}, 
                          {"internalType": "uint256", "name": "amount", "type": "uint256"}],
                "name": "transfer",
                "outputs": [{"internalType": "bool", "type": "bool"}],
                "type": "function"
            }
        ]
        
        # Taxas de conversão (valores em USD aproximados)
        self.token_prices = {
            'MATIC': 0.7,  # Exemplo: $0.70 por MATIC
            'USDT': 1.0,   # Stablecoin
            'ALZ': 0.10    # Nosso token
        }
        
        logger.info(f"✅ Polygon Payment Processor inicializado - Conexão: {self.w3.is_connected()}")

    def validate_address(self, address):
        """Validar endereço Ethereum/Polygon"""
        try:
            return Web3.is_address(address)
        except:
            return False

    def get_token_balance(self, address, token_contract=None):
        """Obter saldo de token específico"""
        try:
            address = Web3.to_checksum_address(address)
            
            if token_contract:
                # Saldo de token ERC20
                contract = self.w3.eth.contract(address=token_contract, abi=self.erc20_abi)
                balance = contract.functions.balanceOf(address).call()
                decimals = contract.functions.decimals().call()
                return balance / (10 ** decimals)
            else:
                # Saldo de MATIC nativo
                balance = self.w3.eth.get_balance(address)
                return self.w3.from_wei(balance, 'ether')
                
        except Exception as e:
            logger.error(f"❌ Erro ao obter saldo: {e}")
            return 0

    def create_payment_request(self, email, amount_brl, currency='USDT'):
        """
        Criar solicitação de pagamento na rede Polygon
        
        Args:
            email: Email do comprador
            amount_brl: Valor em BRL que o usuário quer pagar
            currency: MATIC, USDT, ou ALZ
            
        Returns:
            Dict com dados do pagamento
        """
        try:
            # Calcular quantidade de tokens baseado no valor BRL
            if currency == 'USDT':
                # USDT = BRL (já que 1 USDT ≈ 1 USD ≈ 5 BRL)
                token_amount = Decimal(str(amount_brl))
            elif currency == 'MATIC':
                # MATIC: converter BRL para MATIC via taxa
                matic_price_brl = self.token_prices['MATIC'] * 5  # 1 USD = 5 BRL
                token_amount = Decimal(str(amount_brl)) / Decimal(str(matic_price_brl))
            elif currency == 'ALZ':
                # ALZ: 1 ALZ = R$ 0,10
                token_amount = Decimal(str(amount_brl)) / Decimal('0.10')
            else:
                raise ValueError(f"Moeda não suportada: {currency}")
            
            # Gerar ID único para o pagamento
            payment_id = f"polygon_{int(asyncio.get_event_loop().time())}_{email}"
            
            payment_data = {
                'payment_id': payment_id,
                'network': self.network_name,
                'master_wallet': self.master_wallet,
                'currency': currency,
                'amount_brl': float(amount_brl),
                'token_amount': float(token_amount),
                'required_amount': str(token_amount),
                'email': email,
                'status': 'pending',
                'created_at': self.w3.eth.get_block('latest')['timestamp'],
                'expires_at': self.w3.eth.get_block('latest')['timestamp'] + (30 * 60)  # 30 minutos
            }
            
            logger.info(f"✅ Solicitação de pagamento Polygon criada: {payment_id}")
            return payment_data
            
        except Exception as e:
            logger.error(f"❌ Erro ao criar pagamento Polygon: {e}")
            return None

    def send_alz_tokens(self, to_address, amount_alz):
        """
        Enviar tokens ALZ para o usuário após confirmação do pagamento
        
        Args:
            to_address: Endereço do usuário
            amount_alz: Quantidade de ALZ a enviar
            
        Returns:
            Hash da transação
        """
        try:
            if not self.alz_contract_address:
                logger.error("❌ Contrato ALZ não configurado na Polygon")
                return None
            
            to_address = Web3.to_checksum_address(to_address)
            contract = self.w3.eth.contract(address=self.alz_contract_address, abi=self.erc20_abi)
            
            # Converter para wei (assumindo 18 decimais)
            amount_wei = int(amount_alz * (10 ** 18))
            
            # Construir transação
            nonce = self.w3.eth.get_transaction_count(self.master_wallet)
            
            transaction = contract.functions.transfer(to_address, amount_wei).build_transaction({
                'chainId': self.chain_id,
                'gas': 100000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': nonce,
            })
            
            # Assinar transação
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            
            # Enviar transação
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            logger.info(f"✅ ALZ enviados: {amount_alz} para {to_address} - TX: {tx_hash.hex()}")
            return tx_hash.hex()
            
        except Exception as e:
            logger.error(f"❌ Erro ao enviar ALZ: {e}")
            return None

    def check_payment_status(self, payment_data):
        """
        Verificar se o pagamento foi recebido
        
        Args:
            payment_data: Dados do pagamento criado anteriormente
            
        Returns:
            Dict com status e detalhes
        """
        try:
            # Verificar transações recebidas na wallet mestre
            current_block = self.w3.eth.block_number
            from_block = max(0, current_block - 1000)  # Últimos 1000 blocos
            
            # Filtrar transações para a wallet mestre
            transactions = self.w3.eth.get_transactions_by_address(self.master_wallet, from_block=from_block)
            
            for tx in transactions:
                if (tx['to'] and tx['to'].lower() == self.master_wallet.lower()):
                    # Verificar se o valor corresponde
                    value_eth = self.w3.from_wei(tx['value'], 'ether')
                    
                    # Aqui você implementaria lógica mais sofisticada para 
                    # correlacionar transações com pagamentos pendentes
                    
                    # Por enquanto, retornamos status pendente
                    # Em produção, você implementaria matching por valor/exact amount
                    
                    return {
                        'status': 'pending',
                        'confirmations': 0,
                        'tx_hash': tx['hash'].hex() if hasattr(tx['hash'], 'hex') else str(tx['hash'])
                    }
            
            return {'status': 'pending', 'confirmations': 0}
            
        except Exception as e:
            logger.error(f"❌ Erro ao verificar pagamento: {e}")
            return {'status': 'error', 'error': str(e)}

    def get_network_info(self):
        """Obter informações da rede"""
        try:
            return {
                'network': self.network_name,
                'chain_id': self.chain_id,
                'block_number': self.w3.eth.block_number,
                'gas_price': self.w3.eth.gas_price,
                'is_connected': self.w3.is_connected()
            }
        except Exception as e:
            logger.error(f"❌ Erro ao obter info da rede: {e}")
            return None