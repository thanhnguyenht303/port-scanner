from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from .service import get_service_name

@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str

@dataclass(frozen=True)
class ScanSummary:
    target: str
    ip_address: str
    start_port: int
    end_port: int
    timeout: float
    workers: int
    scanned_at_utc: str
    duration_seconds: float
    open_ports: list[OpenPort]

    @property
    def total_scanned(self) -> int:
        return self.end_port - self.start_port + 1
    
def validate_port_range(start_port: int, end_port: int) -> None: 
    if not(1 <= start_port <= 65535):
        raise ValueError("start_port must be between 1 and 65535")
    if not(1 <= end_port <= 65535):
        raise ValueError("end_port must be between 1 and 65535")
    if start_port > end_port:
        raise ValueError("start_port cannot be greater than end_port")

def resolve_target(target: str) -> tuple[str, str]:
    try: 
        ip_address = socket.gethostbyname(target)
        return target, ip_address
    except socket.gaierror as exc:
        raise ValueError(f"Cloud not resolve host '{target}'") from exc

def scan_port(ip_address: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            return result == 0
    except OSError:
        return False

def run_scan(target: str, ip_address: str, start_port: int, end_port: int, timeout: float, workers: int, on_open: Optional[Callable[[OpenPort], None]] = None) -> ScanSummary:
    validate_port_range(start_port, end_port)

    started = time.perf_counter()
    found: list[OpenPort] = []

    with ThreadPoolExecutor(max_workers= workers) as executor:
        futures = {
            executor.submit(scan_port, ip_address, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            port = futures[future]
            is_open = future.result()

            if is_open:
                result = OpenPort(port=port, service=get_service_name(port))
                found.append(result)
        
    found.sort(key=lambda item: item.port)
    duration = round(time.perf_counter() - start_port, 4)

    return ScanSummary(
        target=target,
        ip_address=ip_address,
        start_port=start_port,
        end_port=end_port,
        timeout=timeout,
        workers=workers,
        scanned_at_utc=datetime.now(timezone.utc).isoformat(),
        duration_seconds=duration,
        open_ports=found
    )