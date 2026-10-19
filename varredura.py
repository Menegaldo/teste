#!/usr/bin/env python3
"""Varredura TCP de um IP com identificacao de servicos por respostas reais.

Exemplos:
    python3 varredura.py 192.168.139.12 -p 51062
    python3 varredura.py 192.168.139.12 -p 1-65535 -j 32
    python3 varredura.py 127.0.0.1 -p 22,80,443,51062 --processos

Usa apenas a biblioteca padrao. Nao consulta servicos externos.
Banner e HTTP/TLS identificam alguns protocolos; ausencia de identificacao
nao altera uma porta ja confirmada como aberta. Nomes pelo numero da porta
sao apenas sugestoes. Processo/PID exige consulta local e permissoes.
"""

import argparse
import errno
import ipaddress
import math
import re
import socket
import ssl
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


DEFAULT_PORTS = (
    "22,53,80,135,139,443,445,631,3389,"
    "5432,5900,5901,5903,8000,8080,8443"
)
TLS_PORTS = {443,465,563,636,853,989,990,992,993,994,995,8443,9443}
UNKNOWN = "nao identificado"
MAX_RESPONSE = 4096


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


def read_response(connection, deadline):
    """Leitura limitada por tamanho e prazo, tolerando respostas fragmentadas."""
    data = bytearray()
    while len(data) < MAX_RESPONSE:
        try:
            remaining(connection, deadline)
            block = connection.recv(MAX_RESPONSE - len(data))
        except (OSError, TimeoutError):
            break
        if not block:
            break
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


def probe_http(connection, request, deadline):
    remaining(connection, deadline)
    connection.sendall(request)
    data = read_response(connection, deadline)
    return classify_response(data)


def probe_tls(family, endpoint, request, deadline):
    # A verificacao de identidade do certificado nao faz parte desta deteccao.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.socket(family, socket.SOCK_STREAM) as raw:
        remaining(raw, deadline)
        raw.connect(endpoint)
        remaining(raw, deadline)
        with context.wrap_socket(raw) as secure:
            version = secure.version() or "TLS"
            try:
                name, evidence = probe_http(secure, request, deadline)
            except (OSError, TimeoutError):
                return "TLS", version + "; protocolo de aplicacao nao identificado"
            if name == "HTTP":
                return "HTTPS", f"{version}; {evidence}"
            if name != UNKNOWN:
                return name + " sobre TLS", f"{version}; {evidence}"
            return "TLS", version + "; protocolo de aplicacao nao identificado"


def identify_service(connection, family, address, port, timeout):
    deadline = time.monotonic() + timeout
    passive_deadline = min(deadline, time.monotonic() + min(0.25, timeout * 0.2))
    banner = read_response(connection, passive_deadline)
    if banner:
        return classify_response(banner)

    endpoint = (address[0], port, *address[2:])
    request = http_request(address[0])
    methods = ("tls", "http") if port in TLS_PORTS else ("http", "tls")
    last_evidence = "sem resposta reconhecivel aos testes HTTP/TLS"

    for index, method in enumerate(methods):
        # Cada tentativa recebe uma parte do prazo total, sem bloquear a seguinte.
        left = deadline - time.monotonic()
        if left <= 0:
            break
        attempt_deadline = time.monotonic() + left / (len(methods) - index)
        try:
            if method == "tls":
                name, evidence = probe_tls(family, endpoint, request, attempt_deadline)
            else:
                name, evidence = probe_http(connection, request, attempt_deadline)
            if name != UNKNOWN:
                return name, evidence
            if evidence != "sem banner":
                last_evidence = evidence
        except (OSError, TimeoutError):
            continue
    return UNKNOWN, last_evidence


def probe(family, address, port, timeout, service_timeout=2.0, services=True):
    endpoint = (address[0], port, *address[2:])
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(endpoint)
            name, evidence = "nao consultado", "-"
            if services:
                try:
                    name, evidence = identify_service(
                        connection, family, address, port, service_timeout
                    )
                except (OSError, TimeoutError):
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


def local_processes(ip):
    """Consulta listeners TCP do proprio host; nao executa comandos remotos."""
    target = ipaddress.ip_address(ip)
    try:
        result = subprocess.run(
            ["ss", "-H", "-lntp", "-4" if target.version == 4 else "-6"],
            capture_output=True, text=True, check=True, timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return {}, "consulta de processos indisponivel; precisa do comando ss"
    processes = {}
    for line in result.stdout.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 6:
            continue
        host, _, port = fields[3].rpartition(":")
        host = host.strip("[]")
        if host not in {ip, "*", "0.0.0.0", "::"} or not port.isdigit():
            continue
        if "users:" in fields[5]:
            processes.setdefault(int(port), []).append(safe_text(fields[5], 400))
    return processes, "processos de outros usuarios podem exigir sudo"


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
        help="mostrar processo/PID local via ss; requer alvo de loopback (127.0.0.1/::1)",
    )
    args = parser.parse_args()
    if args.processos and not ipaddress.ip_address(args.ip).is_loopback:
        parser.error("--processos requer loopback; execute no host alvo usando 127.0.0.1 ou ::1")
    try:
        family, _, _, _, address = socket.getaddrinfo(
            args.ip, 0, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST,
        )[0]
    except OSError as error:
        parser.error(f"IP ou interface indisponivel: {error}")

    workers = min(args.j, len(args.p))
    print(
        f"Alvo: {args.ip} | TCP | portas: {len(args.p)} "
        f"| timeout: {args.t}s | tarefas: {workers}", flush=True,
    )
    if not args.sem_servicos:
        print(f"Identificacao ativa: banner + HTTP/TLS | prazo por porta: {args.service_timeout}s")
    print("PORTA/TCP   RESULTADO      SERVICO                  EVIDENCIA", flush=True)
    started = time.monotonic()
    counts = Counter()
    open_ports = []
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        results = pool.map(
            lambda port: probe(
                family, address, port, args.t, args.service_timeout, not args.sem_servicos
            ),
            args.p,
        )
        for port, state, error_code, service, evidence in results:
            counts[state] += 1
            if state == "aberta":
                open_ports.append(port)
                hint = port_hint(port)
                if hint != "-":
                    evidence += f" | tabela local sugere: {safe_text(hint)} (nao confirma servico)"
            if args.a or state == "aberta":
                if error_code is not None:
                    evidence = f"errno={error_code}"
                print(f"{port:<12}{state:<15}{service:<25}{evidence}", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrompido; encerrando conexoes em andamento.", flush=True)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    if args.processos and open_ports:
        processes, note = local_processes(args.ip)
        print("\nPROCESSOS LOCAIS (listeners TCP visiveis no momento da consulta)")
        for port in open_ports:
            detail = " | ".join(processes.get(port, [])) or "nao visivel / nao encontrado"
            print(f"{port:<12}{detail}")
        print(note)

    finished = sum(counts.values())
    elapsed = time.monotonic() - started
    print(f"\nConcluidas: {finished}/{len(args.p)} | tempo: {elapsed:.2f}s")
    print(
        f"Abertas: {counts['aberta']} | recusadas: {counts['recusada']} "
        f"| sem resposta: {counts['sem_resposta']}"
    )
    print(f"Inacessiveis: {counts['inacessivel']} | erros: {counts['erro']}")
    if not counts["aberta"]:
        print("Nenhuma porta aberta nas conexoes concluidas.")
    if counts["sem_resposta"]:
        print("Sem resposta: conexao nao concluida no prazo; causa indeterminada.")
    if not args.sem_servicos:
        print(
            "Servico nao identificado nao significa porta fechada. "
            "Banners e cabecalhos sao informados pelo destino e podem ser alterados."
        )
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
