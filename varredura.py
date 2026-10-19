#!/usr/bin/env python3
"""Varredura TCP de um IP com identificacao de servicos por respostas reais.

Usa apenas a biblioteca padrao. Nao consulta servicos externos.
Banner e HTTP/TLS identificam alguns protocolos; ausencia de identificacao
nao altera uma porta ja confirmada como aberta. Nomes pelo numero da porta
sao apenas sugestoes. Processo/PID exige consulta local e permissoes.
Conexoes TCP do scanner consigo mesmo sao descartadas, sem contar como abertas.
"""

import argparse
import errno
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_PORTS = (
    "22,53,80,135,139,443,445,631,3389,"
    "5432,5900,5901,5903,8000,8080,8443"
)
TLS_PORTS = {443,465,563,636,853,989,990,992,993,994,995,8443,9443}
UNKNOWN = "nao identificado"
MAX_RESPONSE = 4096
VERSION = "2026.10.19-debug.1"


def endpoint_key(endpoint):
    return tuple(endpoint[:2]) + tuple(endpoint[3:])


def payload_details(data):
    # Bytes exatos do nivel de aplicacao, limitados a MAX_RESPONSE por leitura.
    # Em TLS sao os bytes antes/depois da criptografia, nao uma captura de pacotes.
    return {"bytes": len(data), "data_repr": repr(data), "data_hex": data.hex()}


class Trace:
    """Rastro JSONL e correlacao das conexoes criadas por esta execucao."""

    def __init__(self, console=False, path=None, ports=None):
        self.console = console
        self.file = open(path, "a", encoding="utf-8") if path else None
        self.ports = set(ports) if ports else None
        self.run_id = uuid.uuid4().hex
        self.lock = threading.RLock()
        self.seq = 0
        self.socket_seq = 0
        self.connections = {}
        self.local_target_seen = False
        self.write_error = None

    def event(self, port, event, socket_id=None, **details):
        if not self.console and self.file is None:
            return
        if self.ports is not None and port is not None and port not in self.ports:
            return
        with self.lock:
            self.seq += 1
            record = {
                "seq": self.seq,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "monotonic_ns": time.monotonic_ns(),
                "run_id": self.run_id,
                "scanner_pid": os.getpid(),
                "thread": threading.current_thread().name,
                "port": port,
                "socket_id": socket_id,
                "event": event,
                **details,
            }
            line = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
            if self.file is not None:
                try:
                    self.file.write(line + "\n")
                    self.file.flush()
                except OSError as error:
                    self.write_error = str(error)
                    print(f"ERRO: arquivo de debug incompleto: {error}", file=sys.stderr)
                    self.file.close()
                    self.file = None
            if self.console:
                print("[DEBUG] " + line, file=sys.stderr, flush=True)

    def begin(self, port, phase, endpoint, timeout):
        with self.lock:
            self.socket_seq += 1
            attempt = {
                "id": f"s{self.socket_seq:06d}", "port": port, "phase": phase,
                "started": time.monotonic(), "ended": None,
            }
        self.event(port, "connect_start", attempt["id"], phase=phase,
                   destination=list(endpoint), timeout_seconds=timeout)
        return attempt

    def connected(self, attempt, connection):
        local, peer = connection.getsockname(), connection.getpeername()
        with self.lock:
            attempt.update(local=local, peer=peer, fd=connection.fileno())
            self.connections[attempt["id"]] = attempt
            if local[0] == peer[0]:
                self.local_target_seen = True
        self.event(attempt["port"], "connect_ok", attempt["id"],
                   phase=attempt["phase"], source=list(local), destination=list(peer),
                   fd=attempt["fd"], same_endpoint=is_self_connection(connection))

    def failure(self, attempt, connection, error, phase="connect"):
        try:
            local = list(connection.getsockname())
        except OSError:
            local = None
        self.event(attempt["port"], "socket_error", attempt["id"], phase=phase,
                   source=local, error_type=type(error).__name__,
                   errno=getattr(error, "errno", None), message=str(error))

    def end(self, attempt):
        with self.lock:
            attempt["ended"] = time.monotonic()
        self.event(attempt["port"], "socket_closed", attempt["id"],
                   phase=attempt["phase"], source=attempt.get("local"),
                   destination=attempt.get("peer"),
                   duration_ms=round((attempt["ended"] - attempt["started"]) * 1000, 3))

    def audit(self, results):
        """Descarta pares reversos de sockets do proprio scanner, nao banners ecoados.

        A correlacao exige extremos TCP invertidos e intervalos sobrepostos.
        Um servidor echo real continua aberto, pois seu socket aceito nao foi
        criado por um connect do scanner e nao aparece neste registro.
        """
        by_endpoints = {}
        peers = {}
        for item in self.connections.values():
            key = (endpoint_key(item["local"]), endpoint_key(item["peer"]))
            if key[0] == key[1]:
                continue
            for other in by_endpoints.get((key[1], key[0]), []):
                if max(item["started"], other["started"]) <= min(item["ended"], other["ended"]):
                    peers.setdefault(item["id"], []).append(other)
                    peers.setdefault(other["id"], []).append(item)
            by_endpoints.setdefault(key, []).append(item)
        primary = {item["port"]: item for item in self.connections.values()
                   if item["phase"] == "tcp"}
        audited = []
        for result in results:
            port, state, error, service, evidence = result
            own = primary.get(port)
            if state == "aberta" and own and own["id"] in peers:
                matches = peers[own["id"]]
                evidence = (
                    "extremos TCP reversos de sockets deste scanner; "
                    f"sockets={own['id']}," + ",".join(x["id"] for x in matches)
                )
                result = (port, "conexao_scanner", None, "-", evidence)
                self.event(port, "scanner_peer_discarded", own["id"],
                           source=list(own["local"]), destination=list(own["peer"]),
                           peers=[{"socket_id": x["id"], "source": list(x["local"]),
                                   "destination": list(x["peer"])} for x in matches],
                           reason="reverse_endpoints_and_overlapping_lifetimes")
            audited.append(result)
        return audited

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None


def ip_literal(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(
            "informe um unico IP, sem faixa de rede"
        ) from None


def port_list(value):
    ports = set()
    for item in value.split(","):
        item = item.strip()
        try:
            if "-" in item:
                first, last = map(int, item.split("-"))
            else:
                first = last = int(item)
        except ValueError:
            raise argparse.ArgumentTypeError(
                "use portas como 22,443,5901 ou 1-1024"
            ) from None
        if not 1 <= first <= last <= 65535:
            raise argparse.ArgumentTypeError("portas devem estar entre 1 e 65535")
        ports.update(range(first, last + 1))
    return sorted(ports)


def timeout_value(value):
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout deve ser um numero") from None
    if not math.isfinite(timeout) or not 0.05 <= timeout <= 10:
        raise argparse.ArgumentTypeError("timeout deve estar entre 0.05 e 10 segundos")
    return timeout


def worker_count(value):
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("paralelismo deve ser um inteiro") from None
    if not 1 <= count <= 32:
        raise argparse.ArgumentTypeError("paralelismo deve estar entre 1 e 32")
    return count


def safe_text(data, limit=220):
    """Nao permite que controles de um banner alterem o terminal."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    return " ".join(
        "".join(char if char.isprintable() else " " for char in data).split()
    )[:limit]


def port_hint(port):
    """Consulta a tabela local de portas; isto nao detecta um protocolo."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def is_self_connection(connection):
    """No scan do proprio host, connect pode conectar o socket a si mesmo.

    Isso acontece quando IP e porta de origem coincidem com os de destino,
    mesmo sem listener. O socket recebe os proprios dados enviados.
    O escopo IPv6 tambem precisa coincidir; flowinfo nao identifica o endpoint.
    """
    local = connection.getsockname()
    peer = connection.getpeername()
    return local[:2] == peer[:2] and local[3:] == peer[3:]


def classify_response(data):
    """Retorna servico e evidencia; nunca deduz servico pelo numero da porta."""
    first_line = data.split(b"\n", 1)[0].rstrip(b"\r")
    upper = first_line.upper()
    if re.match(br"SSH-\d+\.\d+-", first_line):
        return "SSH", safe_text(first_line)
    if re.match(br"RFB \d{3}\.\d{3}", first_line):
        return "VNC", safe_text(first_line)
    if re.match(br"HTTP/\d(?:\.\d)? [1-5]\d\d(?: |$)", first_line):
        server = re.search(br"(?im)^Server:[ \t]*([^\r\n]+)", data)
        detail = safe_text(first_line)
        if server:
            detail += "; Server: " + safe_text(server.group(1), 120)
        return "HTTP", detail
    if first_line.startswith(b"220"):
        if b"SMTP" in upper:
            return "SMTP", safe_text(first_line)
        if b"FTP" in upper:
            return "FTP", safe_text(first_line)
    if upper.startswith((b"* OK", b"* PREAUTH")):
        return "IMAP", safe_text(first_line)
    if upper.startswith(b"+OK") and b"POP3" in upper:
        return "POP3", safe_text(first_line)
    if len(data) > 5 and data[3:5] == b"\x00\x0a":
        version = data[5:].split(b"\x00", 1)[0]
        if re.match(br"\d+\.\d+", version):
            return "MySQL compativel", "greeting: " + safe_text(version)
    if upper.startswith(b"-ERR") and b"UNKNOWN COMMAND" in upper:
        return "RESP/Redis provavel", safe_text(first_line)
    return UNKNOWN, "banner: " + safe_text(data) if data else "sem banner"


def remaining(connection, deadline):
    timeout = deadline - time.monotonic()
    if timeout <= 0:
        raise TimeoutError("tempo de identificacao esgotado")
    connection.settimeout(timeout)


def read_response(connection, deadline, trace=None, port=None, socket_id=None, phase="banner"):
    """Leitura limitada por tamanho e prazo, tolerando respostas fragmentadas."""
    data = bytearray()
    while len(data) < MAX_RESPONSE:
        try:
            remaining(connection, deadline)
            block = connection.recv(MAX_RESPONSE - len(data))
        except (OSError, TimeoutError) as error:
            if trace:
                trace.event(port, "read_timeout" if isinstance(error, TimeoutError) else "read_error",
                            socket_id, phase=phase, error_type=type(error).__name__,
                            errno=getattr(error, "errno", None), message=str(error),
                            received_bytes=len(data))
            break
        if not block:
            if trace:
                trace.event(port, "read_eof", socket_id, phase=phase, received_bytes=len(data))
            break
        if trace:
            trace.event(port, "rx", socket_id, phase=phase, **payload_details(block))
        data.extend(block)
        if data.startswith(b"HTTP/"):
            if b"\r\n\r\n" in data or b"\n\n" in data:
                break
        elif b"\n" in data:
            break
        elif len(data) > 5 and data[3:5] == b"\x00\x0a":
            if b"\x00" in data[5:]:
                break
    return bytes(data)


def http_request(ip):
    host = f"[{ip}]" if ":" in ip else ip
    return (
        f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def probe_http(connection, request, deadline, trace=None, port=None, socket_id=None, phase="http"):
    remaining(connection, deadline)
    if trace:
        trace.event(port, "tx_start", socket_id, phase=phase, **payload_details(request))
    try:
        connection.sendall(request)
    except OSError as error:
        if trace:
            trace.event(port, "tx_error", socket_id, phase=phase,
                        error_type=type(error).__name__, message=str(error),
                        partial_send_possible=True)
        raise
    if trace:
        trace.event(port, "tx_complete", socket_id, phase=phase, bytes=len(request))
    data = read_response(connection, deadline, trace, port, socket_id, phase)
    name, evidence = classify_response(data)
    if trace:
        trace.event(port, "classification", socket_id, phase=phase, service=name,
                    evidence=evidence, basis="response_bytes", port_number_is_proof=False,
                    own_request_echo=data == request,
                    own_request_prefix=bool(data) and data.startswith(request.split(b"\r\n", 1)[0]))
    return name, evidence


def probe_tls(family, endpoint, request, deadline, trace=None, port=None):
    # A verificacao de identidade do certificado nao faz parte desta deteccao.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    trace = trace or Trace()
    port = port if port is not None else endpoint[1]
    attempt = trace.begin(port, "tls", endpoint, max(0, deadline - time.monotonic()))
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            try:
                remaining(raw, deadline)
                raw.connect(endpoint)
            except OSError as error:
                trace.failure(attempt, raw, error)
                raise
            trace.connected(attempt, raw)
            if is_self_connection(raw):
                trace.event(port, "self_connection_discarded", attempt["id"],
                            reason="source_equals_destination", phase="tls")
                raise OSError(errno.ECONNREFUSED, "auto-conexao do scanner descartada")
            remaining(raw, deadline)
            trace.event(port, "tls_handshake_start", attempt["id"],
                        certificate_identity_checked=False,
                        wire_packets_captured=False)
            try:
                secure = context.wrap_socket(raw)
            except OSError as error:
                trace.event(port, "tls_handshake_error", attempt["id"],
                            error_type=type(error).__name__, message=str(error))
                raise
            with secure:
                version = secure.version() or "TLS"
                cert = secure.getpeercert(binary_form=True)
                trace.event(port, "tls_handshake_ok", attempt["id"],
                            tls_version=version, cipher=secure.cipher(),
                            certificate_sha256=hashlib.sha256(cert).hexdigest() if cert else None)
                try:
                    name, evidence = probe_http(
                        secure, request, deadline, trace, port, attempt["id"], "http_over_tls"
                    )
                except (OSError, TimeoutError):
                    return "TLS", version + "; protocolo de aplicacao nao identificado"
                if name == "HTTP":
                    return "HTTPS", f"{version}; {evidence}"
                if name != UNKNOWN:
                    return name + " sobre TLS", f"{version}; {evidence}"
                return "TLS", version + "; protocolo de aplicacao nao identificado"
    finally:
        trace.end(attempt)


def identify_service(connection, family, address, port, timeout, trace=None, socket_id=None):
    deadline = time.monotonic() + timeout
    passive_deadline = min(deadline, time.monotonic() + min(0.25, timeout * 0.2))
    if trace:
        trace.event(port, "banner_wait", socket_id,
                    timeout_seconds=max(0, passive_deadline - time.monotonic()))
    banner = read_response(connection, passive_deadline, trace, port, socket_id, "banner")
    if banner:
        name, evidence = classify_response(banner)
        if trace:
            trace.event(port, "classification", socket_id, phase="banner", service=name,
                        evidence=evidence, basis="response_bytes", port_number_is_proof=False)
        return name, evidence

    endpoint = (address[0], port, *address[2:])
    request = http_request(address[0])
    methods = ("tls", "http") if port in TLS_PORTS else ("http", "tls")
    if trace:
        trace.event(port, "probe_plan", socket_id, methods=list(methods),
                    note="numero da porta seleciona somente a ordem, nao identifica o servico")
    last_evidence = "sem resposta reconhecivel aos testes HTTP/TLS"

    for index, method in enumerate(methods):
        # Cada tentativa recebe uma parte do prazo total, sem bloquear a seguinte.
        left = deadline - time.monotonic()
        if left <= 0:
            break
        attempt_deadline = time.monotonic() + left / (len(methods) - index)
        try:
            if method == "tls":
                name, evidence = probe_tls(family, endpoint, request, attempt_deadline, trace, port)
            else:
                name, evidence = probe_http(
                    connection, request, attempt_deadline, trace, port, socket_id
                )
            if name != UNKNOWN:
                return name, evidence
            if evidence != "sem banner":
                last_evidence = evidence
        except (OSError, TimeoutError) as error:
            if trace:
                trace.event(port, "probe_error", socket_id, method=method,
                            error_type=type(error).__name__, message=str(error))
            continue
    return UNKNOWN, last_evidence


def probe(family, address, port, timeout, service_timeout=2.0, services=True, trace=None):
    endpoint = (address[0], port, *address[2:])
    trace = trace or Trace()
    attempt = trace.begin(port, "tcp", endpoint, timeout)
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            try:
                connection.connect(endpoint)
            except OSError as error:
                trace.failure(attempt, connection, error)
                raise
            trace.connected(attempt, connection)
            if is_self_connection(connection):
                trace.event(port, "self_connection_discarded", attempt["id"],
                            source=list(connection.getsockname()),
                            destination=list(connection.getpeername()),
                            reason="source_equals_destination")
                return (
                    port, "auto_conexao", None, "-",
                    "IP/porta de origem e destino identicos; sem listener confirmado",
                )
            name, evidence = "nao consultado", "-"
            if services:
                try:
                    name, evidence = identify_service(
                        connection, family, address, port, service_timeout, trace, attempt["id"]
                    )
                except (OSError, TimeoutError) as error:
                    trace.event(port, "identification_error", attempt["id"],
                                error_type=type(error).__name__, message=str(error),
                                tcp_still_classified_open=True)
                    name, evidence = UNKNOWN, "identificacao interrompida pelo destino"
            return port, "aberta", None, name, evidence
    except TimeoutError:
        return port, "sem_resposta", None, "-", "-"
    except ConnectionRefusedError:
        return port, "recusada", None, "-", "-"
    except OSError as error:
        unreachable = {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}
        state = "inacessivel" if error.errno in unreachable else "erro"
        return port, state, error.errno, "-", "-"
    finally:
        trace.end(attempt)


def is_local_ip(ip, trace):
    if ipaddress.ip_address(ip).is_loopback:
        return True
    command = ["ip", "-j", "address", "show"]
    trace.event(None, "local_command", command=command, purpose="confirmar IP local")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=3)
        target = ipaddress.ip_address(ip.split("%", 1)[0])
        for interface in json.loads(result.stdout):
            for info in interface.get("addr_info", []):
                if ipaddress.ip_address(info["local"].split("%", 1)[0]) == target:
                    trace.event(None, "target_is_local", ip=ip, interface=interface.get("ifname"))
                    return True
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        trace.event(None, "local_command_error", command=command,
                    error_type=type(error).__name__, message=str(error))
    return False


def local_processes(ip, trace=None, snapshot="after", ports=None):
    """Consulta listeners TCP do proprio host; nao executa comandos remotos."""
    command = ["ss", "-H", "-lntp"]
    if trace:
        trace.event(None, "local_command", command=command, purpose="listeners TCP", snapshot=snapshot)
    try:
        result = subprocess.run(
            command,
            capture_output=True, text=True, check=True, timeout=3,
        )
    except (OSError, subprocess.SubprocessError) as error:
        if trace:
            trace.event(None, "local_command_error", command=command, snapshot=snapshot,
                        error_type=type(error).__name__, message=str(error))
        return {}, "consulta de processos indisponivel; precisa do comando ss"
    processes = {}
    selected = set(ports) if ports is not None else None
    for line in result.stdout.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            continue
        host, _, port = fields[3].rpartition(":")
        host = host.strip("[]")
        if host not in {ip, "*", "0.0.0.0", "::"} or not port.isdigit():
            continue
        port = int(port)
        if selected is not None and port not in selected:
            continue
        owner = fields[5] if len(fields) == 6 and "users:" in fields[5] else "processo/PID nao visivel"
        detail = safe_text(f"bind={fields[3]} {owner}", 600)
        processes.setdefault(port, []).append(detail)
        if trace:
            trace.event(port, "local_listener", snapshot=snapshot, bind=fields[3],
                        process_info=safe_text(owner, 400),
                        wildcard_ipv6_candidate=host in {"*", "::"},
                        note="listener visivel neste instante; wildcard IPv6 pode depender de dual-stack")
    if trace:
        trace.event(None, "local_snapshot_complete", snapshot=snapshot, ip=ip,
                    listener_ports=sorted(processes), command_returncode=result.returncode)
    return processes, "Ausencia neste instante nao exclui listener transitorio; outros usuarios podem exigir sudo."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "ip", nargs="?", type=ip_literal, default="127.0.0.1",
        help="IP alvo; padrao: 127.0.0.1",
    )
    parser.add_argument(
        "-p", type=port_list, default=DEFAULT_PORTS, metavar="PORTAS",
        help="portas e faixas separadas por virgula",
    )
    parser.add_argument(
        "-t", type=timeout_value, default=1.0, metavar="SEGUNDOS",
        help="timeout por conexao TCP; padrao: 1",
    )
    parser.add_argument(
        "-j", type=worker_count, default=8, metavar="CONEXOES",
        help="tarefas simultaneas; padrao: 8, maximo: 32",
    )
    parser.add_argument("-a", action="store_true", help="mostrar tambem portas nao abertas")
    parser.add_argument(
        "--service-timeout", type=timeout_value, default=2.0, metavar="SEGUNDOS",
        help="prazo total de identificacao por porta aberta; padrao: 2",
    )
    parser.add_argument(
        "--sem-servicos", action="store_true", help="somente verificar conexao TCP",
    )
    parser.add_argument(
        "--processos", action="store_true",
        help="consultar listeners/processos locais antes e depois; requer executar no host alvo",
    )
    parser.add_argument(
        "--debug", action="store_true", help="mostrar eventos detalhados no terminal (stderr)",
    )
    parser.add_argument(
        "--debug-arquivo", metavar="ARQUIVO.jsonl",
        help="gravar eventos JSONL; acrescenta uma execucao identificada ao arquivo",
    )
    parser.add_argument(
        "--debug-portas", type=port_list, metavar="PORTAS",
        help="limitar os eventos de debug a estas portas; nao altera as portas do scan",
    )
    parser.add_argument("--versao", action="version", version=VERSION)
    args = parser.parse_args()
    if args.debug_portas and not (args.debug or args.debug_arquivo):
        parser.error("--debug-portas requer --debug ou --debug-arquivo")
    try:
        family, _, _, _, address = socket.getaddrinfo(
            args.ip, 0, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST,
        )[0]
    except OSError as error:
        parser.error(f"IP ou interface indisponivel: {error}")

    try:
        trace = Trace(args.debug, args.debug_arquivo, args.debug_portas)
    except OSError as error:
        parser.error(f"nao foi possivel abrir o arquivo de debug: {error}")
    workers = min(args.j, len(args.p))
    try:
        script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        script_hash = None
    trace.event(None, "scan_start", version=VERSION, script_sha256=script_hash,
                argv=sys.argv, target=args.ip, port_count=len(args.p),
                workers=workers, connect_timeout_seconds=args.t,
                service_timeout_seconds=args.service_timeout,
                service_probes_enabled=not args.sem_servicos,
                debug_ports=args.debug_portas, hostname=socket.gethostname(),
                python=sys.version.split()[0], pid=os.getpid(),
                application_bytes_logged=True, wire_packets_captured=False)
    print(
        f"Alvo: {args.ip} | TCP | portas: {len(args.p)} "
        f"| timeout: {args.t}s | tarefas: {workers}", flush=True,
    )
    print(f"Scanner: pid={os.getpid()} | versao={VERSION} | execucao={trace.run_id}", flush=True)
    if args.debug_arquivo:
        print(f"Debug JSONL: {args.debug_arquivo} (eventos desta execucao tem o mesmo run_id)", flush=True)
    if not args.sem_servicos:
        print(f"Identificacao ativa: banner + HTTP/TLS | prazo por porta: {args.service_timeout}s")
    local_before = args.processos and is_local_ip(args.ip, trace)
    before, before_note = ({}, "consulta anterior nao realizada")
    if local_before:
        before, before_note = local_processes(args.ip, trace, "before", args.p)
    started = time.monotonic()
    collected = []
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        results = pool.map(
            lambda port: probe(
                family, address, port, args.t, args.service_timeout, not args.sem_servicos, trace
            ),
            args.p,
        )
        for result in results:
            collected.append(result)
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrompido; encerrando conexoes em andamento.", flush=True)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    results = trace.audit(collected)
    counts = Counter(result[1] for result in results)
    visible_ports = {r[0] for r in results if r[1] in {"aberta", "auto_conexao", "conexao_scanner"}}
    print("\nPORTA/TCP   RESULTADO          SERVICO                  EVIDENCIA", flush=True)
    for port, state, error_code, service, evidence in results:
        hint = port_hint(port) if state == "aberta" else "-"
        trace.event(port, "scan_result", state=state, service=service, evidence=evidence,
                    errno=error_code, local_port_name_hint=hint, hint_confirms_service=False)
        if hint != "-":
            evidence += f" | tabela local sugere: {safe_text(hint)} (nao confirma servico)"
        if args.a or state in {"aberta", "auto_conexao", "conexao_scanner"}:
            if error_code is not None:
                evidence = f"errno={error_code}"
            print(f"{port:<12}{state:<19}{service:<25}{evidence}", flush=True)

    if args.processos:
        if local_before or trace.local_target_seen:
            after, note = local_processes(args.ip, trace, "after", args.p)
            print("\nLISTENERS LOCAIS: consultas antes/depois, com bind e processo/PID quando visivel")
            for port in sorted(visible_ports | set(before) | set(after)):
                first = " | ".join(before.get(port, [])) or (
                    "nao visto" if local_before else "nao consultado"
                )
                last = " | ".join(after.get(port, [])) or "nao visto"
                print(f"{port:<12}ANTES: {first}\n{'':12}DEPOIS: {last}")
            print(note)
            if local_before and before_note.startswith("consulta de processos indisponivel"):
                print(before_note)
        else:
            print("Processos locais: alvo nao confirmado como IP deste host. Execute --processos no alvo.")
            trace.event(None, "local_processes_unavailable", reason="target_not_confirmed_local")

    finished = sum(counts.values())
    elapsed = time.monotonic() - started
    print(f"\nConcluidas: {finished}/{len(args.p)} | tempo: {elapsed:.2f}s")
    print(
        f"Abertas: {counts['aberta']} | recusadas: {counts['recusada']} "
        f"| sem resposta: {counts['sem_resposta']}"
    )
    print(f"Inacessiveis: {counts['inacessivel']} | erros: {counts['erro']}")
    if counts["auto_conexao"] or counts["conexao_scanner"]:
        print(
            f"Conexoes do scanner descartadas: consigo mesmo={counts['auto_conexao']} "
            f"| entre sockets do scanner={counts['conexao_scanner']}"
        )
    if not counts["aberta"]:
        print("Nenhuma porta aberta nas conexoes concluidas.")
    if counts["sem_resposta"]:
        print("Sem resposta: conexao nao concluida no prazo; causa indeterminada.")
    if not args.sem_servicos:
        print(
            "Servico nao identificado nao significa porta fechada. "
            "Banners e cabecalhos sao informados pelo destino e podem ser alterados."
        )
    trace.event(None, "scan_finished", completed=finished, requested=len(args.p),
                elapsed_seconds=round(elapsed, 6), counts=dict(counts), interrupted=interrupted,
                debug_write_error=trace.write_error)
    trace.close()
    return 130 if interrupted else (1 if trace.write_error else 0)


if __name__ == "__main__":
    raise SystemExit(main())
