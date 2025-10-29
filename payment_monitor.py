# payments/payment_monitor.py
import asyncio
import time
import logging
from threading import Thread
from datetime import datetime, timedelta
from typing import Dict, List, Callable

logger = logging.getLogger(__name__)

class PaymentMonitor:
    def __init__(self):
        self.active_payments: Dict[str, dict] = {}
        self.processors = {}  # Será preenchido com os processadores de cada rede
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Callbacks para eventos
        self.on_payment_received: Callable = None
        self.on_payment_confirmed: Callable = None
        self.on_payment_expired: Callable = None
        
        logger.info("✅ Payment Monitor inicializado")

    def register_processor(self, network_name, processor):
        """Registrar um processador de pagamento para uma rede"""
        self.processors[network_name] = processor
        logger.info(f"✅ Processador registrado para rede: {network_name}")

    def add_payment(self, payment_data):
        """Adicionar pagamento para monitoramento"""
        payment_id = payment_data['payment_id']
        self.active_payments[payment_id] = {
            **payment_data,
            'last_checked': datetime.now(),
            'check_count': 0
        }
        logger.info(f"✅ Pagamento adicionado para monitoramento: {payment_id}")
        return payment_id

    def remove_payment(self, payment_id):
        """Remover pagamento do monitoramento"""
        if payment_id in self.active_payments:
            del self.active_payments[payment_id]
            logger.info(f"✅ Pagamento removido do monitoramento: {payment_id}")

    def check_single_payment(self, payment_id):
        """Verificar status de um pagamento específico"""
        if payment_id not in self.active_payments:
            return None
            
        payment = self.active_payments[payment_id]
        processor = self.processors.get(payment['network'])
        
        if not processor:
            logger.error(f"❌ Processador não encontrado para rede: {payment['network']}")
            return None
        
        try:
            # Verificar status com o processador específico
            status = processor.check_payment_status(payment)
            
            # Atualizar dados do pagamento
            payment['last_checked'] = datetime.now()
            payment['check_count'] += 1
            payment['last_status'] = status
            
            # Verificar expiração
            if datetime.now().timestamp() > payment['expires_at']:
                payment['status'] = 'expired'
                if self.on_payment_expired:
                    self.on_payment_expired(payment_id, payment)
                logger.info(f"⏰ Pagamento expirado: {payment_id}")
            
            # Verificar se foi confirmado
            if status.get('status') == 'confirmed':
                payment['status'] = 'completed'
                payment['confirmed_at'] = datetime.now()
                if self.on_payment_confirmed:
                    self.on_payment_confirmed(payment_id, payment)
                logger.info(f"✅ Pagamento confirmado: {payment_id}")
            
            return status
            
        except Exception as e:
            logger.error(f"❌ Erro ao verificar pagamento {payment_id}: {e}")
            return {'status': 'error', 'error': str(e)}

    def monitor_loop(self):
        """Loop principal de monitoramento"""
        logger.info("🔄 Iniciando loop de monitoramento de pagamentos...")
        
        while self.is_monitoring:
            try:
                payment_ids = list(self.active_payments.keys())
                
                for payment_id in payment_ids:
                    self.check_single_payment(payment_id)
                
                # Aguardar antes da próxima verificação
                time.sleep(30)  # Verificar a cada 30 segundos
                
            except Exception as e:
                logger.error(f"❌ Erro no loop de monitoramento: {e}")
                time.sleep(60)  # Aguardar mais em caso de erro

    def start_monitoring(self):
        """Iniciar monitoramento em thread separada"""
        if self.is_monitoring:
            logger.warning("⚠️ Monitoramento já está ativo")
            return
            
        self.is_monitoring = True
        self.monitor_thread = Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("🚀 Monitoramento de pagamentos iniciado")

    def stop_monitoring(self):
        """Parar monitoramento"""
        self.is_monitoring = False
        logger.info("🛑 Monitoramento de pagamentos parado")

    def get_active_payments(self):
        """Obter lista de pagamentos ativos"""
        return self.active_payments

    def get_payment_status(self, payment_id):
        """Obter status de um pagamento específico"""
        if payment_id in self.active_payments:
            return self.active_payments[payment_id]
        return None

    def cleanup_expired_payments(self):
        """Limpar pagamentos expirados"""
        now = datetime.now().timestamp()
        expired_ids = []
        
        for payment_id, payment in self.active_payments.items():
            if now > payment['expires_at']:
                expired_ids.append(payment_id)
        
        for payment_id in expired_ids:
            self.remove_payment(payment_id)
            logger.info(f"🧹 Pagamento expirado removido: {payment_id}")
        
        return len(expired_ids)