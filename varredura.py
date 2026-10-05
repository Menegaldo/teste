#!/usr/bin/env python3
"""Enumera portas TCP de um IP por meio de conexoes comuns."""

import argparse
import errno
import ipaddress
import math
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


DEFAULT_PORTS = (
    "22,53,80,135,139,443,445,631,3389,"
    "5432,5900,5901,5903,8000,8080,8443"
)


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
            raise argparse.ArgumentTypeError(
                "portas devem estar entre 1 e 65535"
            )

        ports.update(range(first, last + 1))

    return sorted(ports)


def timeout_value(value):
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "timeout deve ser um numero"
        ) from None

    if not math.isfinite(timeout) or not 0.05 <= timeout <= 10:
        raise argparse.ArgumentTypeError(
            "timeout deve estar entre 0.05 e 10 segundos"
        )

    return timeout


def worker_count(value):
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "paralelismo deve ser um inteiro"
        ) from None

    if not 1 <= count <= 32:
        raise argparse.ArgumentTypeError(
            "paralelismo deve estar entre 1 e 32"
        )

    return count


def probe(family, address, port, timeout):
    endpoint = (address[0], port, *address[2:])

    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(endpoint)

        return port, "aberta", None

    except TimeoutError:
        return port, "sem_resposta", None

    except ConnectionRefusedError:
        return port, "recusada", None

    except OSError as error:
        unreachable = {
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            10065,
            10051,
        }
        state = "inacessivel" if error.errno in unreachable else "erro"
        return port, state, error.errno


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "ip", nargs="?", type=ip_literal, default="127.0.0.1",
        help="IP alvo; padrao: 127.0.0.1"
    )
    parser.add_argument(
        "-p", type=port_list, default=DEFAULT_PORTS,
        metavar="PORTAS",
        help="portas e faixas separadas por virgula"
    )
    parser.add_argument(
        "-t", type=timeout_value, default=1.0,
        metavar="SEGUNDOS",
        help="timeout por conexao; padrao: 1"
    )
    parser.add_argument(
        "-j", type=worker_count, default=8,
        metavar="CONEXOES",
        help="conexoes simultaneas; padrao: 8, maximo: 32"
    )
    parser.add_argument(
        "-a", action="store_true",
        help="mostrar tambem recusas, timeouts e erros"
    )
    args = parser.parse_args()

    try:
        family, _, _, _, address = socket.getaddrinfo(
            args.ip,
            0,
            type=socket.SOCK_STREAM,
            flags=socket.AI_NUMERICHOST,
        )[0]
    except OSError as error:
        parser.error(f"IP ou interface indisponivel: {error}")

    workers = min(args.j, len(args.p))
    print(
        f"Alvo: {args.ip} | TCP | portas: {len(args.p)} "
        f"| timeout: {args.t}s | conexoes: {workers}",
        flush=True,
    )
    print("PORTA/TCP    RESULTADO", flush=True)

    started = time.monotonic()
    counts = Counter()
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=workers)

    try:
        results = pool.map(
            lambda port: probe(family, address, port, args.t),
            args.p,
        )

        for port, state, error_code in results:
            counts[state] += 1

            if args.a or state == "aberta":
                detail = (
                    f" (errno={error_code})"
                    if error_code is not None else ""
                )
                print(f"{port:<12}{state}{detail}", flush=True)

    except KeyboardInterrupt:
        interrupted = True
        print(
            "\nInterrompido; encerrando conexoes em andamento.",
            flush=True,
        )

    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    finished = sum(counts.values())
    elapsed = time.monotonic() - started

    print(f"Concluidas: {finished}/{len(args.p)} | tempo: {elapsed:.2f}s")
    print(
        f"Abertas: {counts['aberta']} "
        f"| recusadas: {counts['recusada']} "
        f"| sem resposta: {counts['sem_resposta']}"
    )
    print(
        f"Inacessiveis: {counts['inacessivel']} "
        f"| erros: {counts['erro']}"
    )

    if not counts["aberta"]:
        print("Nenhuma porta aberta nas conexoes concluidas.")

    if counts["sem_resposta"]:
        print(
            "Sem resposta: conexao nao concluida no prazo; "
            "causa indeterminada."
        )

    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
