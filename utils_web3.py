# payments/utils_web3.py
from web3 import Web3
import json
import logging

logger = logging.getLogger(__name__)

def validate_eth_address(address):
    """Validar endereço Ethereum"""
    try:
        return Web3.is_address(address)
    except:
        return False

def to_checksum_address(address):
    """Converter para checksum address"""
    try:
        return Web3.to_checksum_address(address)
    except:
        return None

def format_token_amount(amount, decimals=18):
    """Formatar quantidade de token para exibição"""
    try:
        return f"{amount:.{decimals}f}"
    except:
        return str(amount)

def calculate_gas_limit(w3, transaction):
    """Calcular limite de gas para transação"""
    try:
        return w3.eth.estimate_gas(transaction)
    except Exception as e:
        logger.error(f"❌ Erro ao calcular gas: {e}")
        return 21000  # Valor mínimo

def get_token_info(w3, contract_address, abi):
    """Obter informações do token"""
    try:
        contract = w3.eth.contract(address=contract_address, abi=abi)
        symbol = contract.functions.symbol().call()
        decimals = contract.functions.decimals().call()
        return {'symbol': symbol, 'decimals': decimals}
    except Exception as e:
        logger.error(f"❌ Erro ao obter info do token: {e}")
        return None