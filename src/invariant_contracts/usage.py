"""Identidade comercial de um host e pseudonimização para a central.

Funções puras, compartilhadas por api (que mede), licensing (que conta) e
testes — a mesma normalização nos dois lados é o que garante que o mesmo
host nunca vire duas cobranças.
"""

import hashlib
import hmac
import ipaddress
import re
from datetime import datetime, timezone

HOST_KINDS = ("linux_host", "docker_container")

_COMPOSE_PROJECT = "com.docker.compose.project"
_COMPOSE_SERVICE = "com.docker.compose.service"
_COMPOSE_NUMBER = "com.docker.compose.container-number"


def normalize_host_ip(ip: str) -> str:
    """Forma canônica de um IP: IPv6 comprimido e minúsculo; IPv4-mapeado
    em IPv6 (::ffff:10.0.0.5) vira o IPv4. Levanta ValueError se não for IP."""
    addr = ipaddress.ip_address(ip.strip())
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.compressed


def _norm_part(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower()).strip("-")


def normalize_container_identity(name: str, labels: dict[str, str] | None = None) -> str:
    """Identidade comercial de um container — nunca o container ID.

    Compose: "compose:<project>/<service>/<número>" — recriar o mesmo
    container lógico mantém a identidade; réplicas diferentes (número) são
    containers diferentes. Fora de compose: "name:<nome normalizado>".
    """
    labels = labels or {}
    project = labels.get(_COMPOSE_PROJECT, "")
    service = labels.get(_COMPOSE_SERVICE, "")
    if project and service:
        number = labels.get(_COMPOSE_NUMBER, "1") or "1"
        return f"compose:{_norm_part(project)}/{_norm_part(service)}/{_norm_part(number)}"
    clean = _norm_part(name.lstrip("/"))
    if not clean:
        raise ValueError("nome de container vazio")
    return f"name:{clean}"


def usage_period(moment: datetime) -> str:
    """Mês civil UTC ("YYYY-MM") de um instante com fuso. Instante sem fuso
    é recusado — ambiguidade de fuso é exatamente o que quebra a virada de mês."""
    if moment.tzinfo is None:
        raise ValueError("datetime sem fuso horário")
    utc = moment.astimezone(timezone.utc)
    return f"{utc.year:04d}-{utc.month:02d}"


def period_bounds(period: str) -> tuple[datetime, datetime]:
    """[início, fim) do período em UTC."""
    year, month = (int(p) for p in period.split("-"))
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=timezone.utc)
    return start, end


def usage_host_hash(usage_hmac_key: bytes, host_kind: str, host_key: str) -> str:
    """Pseudônimo estável de um host para a central. A chave
    (INVARIANT_USAGE_HMAC_KEY) nunca sai do appliance e nunca é rotacionada;
    `host_key` já deve estar normalizado."""
    if host_kind not in HOST_KINDS:
        raise ValueError(f"host_kind inválido: {host_kind}")
    if not usage_hmac_key:
        raise ValueError("chave de uso vazia")
    msg = f"{host_kind}\n{host_key}".encode()
    return hmac.new(usage_hmac_key, msg, hashlib.sha256).hexdigest()
