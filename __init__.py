# payments/__init__.py
from .polygon_payments import PolygonPaymentProcessor
from .ethereum_payments import EthereumPaymentProcessor
from .payment_monitor import PaymentMonitor

# Instância global do monitor
payment_monitor = PaymentMonitor()

def init_payment_system():
    """Inicializar sistema de pagamentos multi-rede"""
    
    # Inicializar processadores
    polygon_processor = PolygonPaymentProcessor()
    ethereum_processor = EthereumPaymentProcessor()
    
    # Registrar processadores no monitor
    payment_monitor.register_processor('Polygon', polygon_processor)
    payment_monitor.register_processor('Ethereum', ethereum_processor)
    
    # Iniciar monitoramento
    payment_monitor.start_monitoring()
    
    return {
        'polygon': polygon_processor,
        'ethereum': ethereum_processor,
        'monitor': payment_monitor
    }

__all__ = [
    'PolygonPaymentProcessor',
    'EthereumPaymentProcessor', 
    'PaymentMonitor',
    'payment_monitor',
    'init_payment_system'
]