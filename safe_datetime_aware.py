from datetime import datetime, timezone

def safe_datetime_aware(dt):
    """
    Garante que um objeto datetime seja timezone-aware (UTC).
    Se o objeto for None ou não for um datetime, retorna o valor original.
    Se for naive, assume UTC. Se for aware, converte para UTC.
    """
    if dt is None or not isinstance(dt, datetime):
        return dt

    # Se for naive (sem fuso horário), assume UTC
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    
    # Se for aware, converte para UTC
    return dt.astimezone(timezone.utc)

def safe_datetime_diff(end_date, start_date=None):
    """
    Calcula a diferença entre duas datas de forma segura, garantindo timezone-awareness.
    Retorna um objeto timedelta.
    """
    if start_date is None:
        start_date = datetime.now(timezone.utc)
        
    aware_end = safe_datetime_aware(end_date)
    aware_start = safe_datetime_aware(start_date)
    
    if aware_end is None or aware_start is None:
        # Retorna timedelta zero se alguma data for inválida
        return datetime.now(timezone.utc) - datetime.now(timezone.utc)
    
    # A subtração agora é segura, pois ambos são aware (UTC)
    return aware_end - aware_start

