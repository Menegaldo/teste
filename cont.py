import time

segundos = 0

try:
    while True:
        print(f"\rContador: {segundos} segundos", end="", flush=True)
        time.sleep(1)
        segundos += 1
except KeyboardInterrupt:
    print("\nContador encerrado.")
