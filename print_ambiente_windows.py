# python3 print_ambiente_windows.py --repo "SEU_USUARIO/teste-capturas" --token "SEU_TOKEN" --intervalo 30

#!/usr/bin/env python3

"""Captura a tela no Windows e envia PNG + JSON para um repositorio Git.

Requisitos: Windows 11, Python 3 e Git no PATH, Pillow e repositorio
clonado com origin configurado, autenticacao Git e permissao de escrita.
Execute no PowerShell da sessao de desktop que deseja capturar.

Exemplo:
  py print_github_windows.py --repo "C:\\Repos\\capturas" --intervalo 30
  py print_github_windows.py --repo "C:\\Repos\\capturas" --quantidade 1

O programa permanece no terminal e encerra com Ctrl+C. Nao instala servicos.
"""

import argparse
import ctypes
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None


class TestError(Exception):
    pass


def redact(value):
    value = re.sub(r"(https?://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[REMOVIDO]@", value)
    return re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b", "[TOKEN REMOVIDO]", value)


def log(message):
    print(f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] {message}", flush=True)


def git(repo, *arguments):
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", env=env,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TestError(f"Falha em git {arguments[0]}: {redact(detail)}")
    return result.stdout.strip()


def prepare_repo(path):
    if shutil.which("git") is None:
        raise TestError("Instale Git para Windows e reabra o PowerShell.")
    repo = path.expanduser().resolve()
    if not repo.is_dir():
        raise TestError("A pasta do repositorio nao existe. Clone-o primeiro.")
    root = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    if root != repo:
        raise TestError("--repo deve apontar para a raiz do repositorio clonado.")
    if git(repo, "status", "--porcelain"):
        raise TestError("O repositorio possui alteracoes locais. Use um clone limpo.")
    branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    git(repo, "remote", "get-url", "origin")
    # Verifica identidade antes da primeira captura.
    git(repo, "var", "GIT_AUTHOR_IDENT")
    git(repo, "var", "GIT_COMMITTER_IDENT")
    git(repo, "fetch", "origin", f"refs/heads/{branch}")
    if git(repo, "rev-parse", "HEAD") != git(repo, "rev-parse", "FETCH_HEAD"):
        raise TestError("A branch local difere da remota. Atualize-a ou use um clone novo.")
    return repo, branch


def windows_uptime():
    # GetTickCount64 retorna milissegundos desde a inicializacao do sistema.
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetTickCount64
    function.argtypes = []
    function.restype = ctypes.c_ulonglong
    return function() / 1000.0


def capture(repo, all_screens=False):
    folder = repo / "capturas"
    # Rejeita tambem junctions/reparse points do Windows.
    if folder.is_symlink() or (folder.exists() and folder.resolve() != folder.absolute()):
        raise TestError("A pasta capturas nao pode ser um link ou junction.")
    folder.mkdir(exist_ok=True)
    started = datetime.now(timezone.utc)
    basename = started.strftime("print_%Y%m%dT%H%M%S_%fZ")
    image_path = folder / f"{basename}.png"
    metadata_path = folder / f"{basename}.json"
    try:
        screenshot = ImageGrab.grab(all_screens=all_screens)
    except Exception as exc:
        raise TestError(
            "Falha ao capturar a tela. Execute na sessao de desktop do Windows, "
            f"com a tela desbloqueada. Detalhe: {redact(str(exc))}"
        ) from exc
    try:
        completed = datetime.now(timezone.utc)
        metadata = {
            "capture_started_at_utc": started.isoformat(),
            "capture_completed_at_utc": completed.isoformat(),
            "capture_completed_at_local": completed.astimezone().isoformat(),
            "boot_id": None,  # Nao ha leitura de /proc no Windows.
            "system_uptime_seconds": windows_uptime(),
            "session_type": "windows_desktop",
            "operating_system": platform.platform(),
            "all_screens": all_screens,
            "image": image_path.name,
            "image_width": screenshot.width,
            "image_height": screenshot.height,
        }
        screenshot.save(image_path, format="PNG")
    finally:
        screenshot.close()
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return image_path.relative_to(repo).as_posix(), metadata_path.relative_to(repo).as_posix()


def upload(repo, branch, files):
    git(repo, "add", "--", *files)
    # Inclui apenas os dois arquivos desta captura.
    git(repo, "commit", "--only", "-m", f"Captura de tela: {files[0]}", "--", *files)
    git(repo, "push", "origin", f"HEAD:refs/heads/{branch}")


def positive_interval(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Informe um numero de segundos.") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("O intervalo deve ser positivo e finito.")
    return number


def nonnegative_count(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("A quantidade deve ser um inteiro.") from None
    if number < 0:
        raise argparse.ArgumentTypeError("A quantidade deve ser 0 ou um inteiro positivo.")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, type=Path, help="Raiz do repositorio clonado")
    parser.add_argument("--intervalo", type=positive_interval, default=60.0, help="Segundos entre ciclos (padrao: 60)")
    parser.add_argument("--quantidade", type=nonnegative_count, default=0, help="Quantidade de capturas; 0 = ate Ctrl+C")
    parser.add_argument("--todos-monitores", action="store_true", help="Captura todos os monitores; padrao: principal")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.exit(1, "Esta versao deve ser executada no Windows.\n")
    if ImageGrab is None:
        parser.exit(1, "Instale Pillow: py -m pip install Pillow\n")
    try:
        repo, branch = prepare_repo(args.repo)
        log(f"Captura e envio ativos a cada {args.intervalo:g}s. Ctrl+C encerra.")
        completed = 0
        while args.quantidade == 0 or completed < args.quantidade:
            cycle_start = time.monotonic()
            files = capture(repo, args.todos_monitores)
            log(f"Captura salva: {files[0]}")
            upload(repo, branch, files)
            completed += 1
            log(f"Envio confirmado ({completed}): {files[0]}")
            if args.quantidade and completed >= args.quantidade:
                break
            # Nao acumula capturas atrasadas; o envio pode alongar o intervalo.
            time.sleep(max(0.0, args.intervalo - (time.monotonic() - cycle_start)))
        log("Concluido.")
        return 0
    except KeyboardInterrupt:
        log("Encerrado por Ctrl+C.")
        return 130
    except (TestError, OSError, ValueError) as exc:
        log(f"ERRO: {redact(str(exc))}")
        log("Interrompido. Arquivos e commits ja criados permanecem locais.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
