# cat > captura_github.py <<'PY'

# python3 captura_github.py --repo "SEU_USUARIO/teste-capturas" --token "SEU_TOKEN" --intervalo 30

import argparse
import base64
import io
import json
import math
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from PIL import ImageGrab


def intervalo_positivo(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("Informe segundos maiores que zero.")
    return number


def capture_and_upload(repo, token):
    print("Capturando a tela...", flush=True)
    image = ImageGrab.grab()
    try:
        with io.BytesIO() as buffer:
            image.save(buffer, format="PNG")
            content = base64.b64encode(buffer.getvalue()).decode("ascii")
    finally:
        image.close()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    path = f"capturas/print_{timestamp}_{uuid.uuid4().hex[:8]}.png"
    owner, name = (quote(part, safe="") for part in repo.split("/"))

    payload = json.dumps({
        "message": f"Captura de teste: {timestamp}",
        "content": content,
    }).encode("utf-8")

    request = Request(
        f"https://api.github.com/repos/{owner}/{name}/contents/{path}",
        data=payload,
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "captura-github-python",
        },
    )

    print(f"Enviando para {repo}...", flush=True)
    with urlopen(request, timeout=60) as response:
        result = json.load(response)

    print(f"Envio confirmado: {result['content']['html_url']}", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Captura a tela periodicamente e envia ao GitHub."
    )
    parser.add_argument("--repo", required=True, help="USUARIO/REPOSITORIO")
    parser.add_argument("--token", required=True, help="Token do GitHub")
    parser.add_argument(
        "--intervalo",
        required=True,
        type=intervalo_positivo,
        help="Intervalo entre capturas, em segundos",
    )
    args = parser.parse_args()
    args.repo = args.repo.strip()

    parts = args.repo.split("/")
    if len(parts) != 2 or not all(parts):
        parser.error("--repo deve ter o formato USUARIO/REPOSITORIO")

    print(f"Intervalo: {args.intervalo:g}s. Ctrl+C encerra.", flush=True)

    try:
        while True:
            started = time.monotonic()
            capture_and_upload(args.repo, args.token)

            # Evita acumular capturas atrasadas se o envio demorar.
            remaining = args.intervalo - (time.monotonic() - started)
            time.sleep(max(0, remaining))

    except KeyboardInterrupt:
        print("\nCapturas encerradas.")
        return 0
    except HTTPError as exc:
        messages = {
            401: "Token invalido ou expirado.",
            403: "Sem permissao ou limite da API atingido.",
            404: "Repositorio incorreto ou token sem acesso.",
            409: "Conflito no repositorio.",
            422: "Envio recusado pelas regras ou estado do repositorio.",
        }
        print(f"HTTP {exc.code}: {messages.get(exc.code, 'Envio recusado.')}")
    except (URLError, TimeoutError):
        print("Falha de conexao. Confira o ultimo envio no GitHub.")
    except Exception as exc:
        print(f"Falha: {str(exc).replace(args.token, '[TOKEN]')}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
PY
