from Ports import TOP10K
from Ports import TOP1K
import sys
import time
import queue
import threading
import socket
import argparse

from pythonping import ping


arte_ascii = f"""\n        
        Port Scanner
        ⢀⣠⣤⣶⣶⣿⣿⣿⣶⣶⣤⡀
⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀
⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀
⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀
⠀⠀⢸⣿⣿⣿⣿⣿⡏⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀
⠀⠀⠘⣿⣿⣟⡿⢿⣷⢸⠞⠛⢽⣾⣛⡟⣿⣿⣿⠁⠀
⠀⠀⠀⠻⣿⡟⢶⡿⡿⠀⠀⠀⠀⠹⠯⠏⢸⣿⣿⠀⠀
⠀⠀⠀⠀⠛⣾⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⡏⠀⠀
⠀⠀⠀⠀⠀⣿⣿⣄⠀⠀⠈⠍⠀⠀⢀⣼⣿⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠈⠀⠘⢉⠖⠠⠤⠤⠀⠈⡌⣿⡏⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡠⠔⠊⠀⠀⠀⠀⠀⠀⠈⣿⡀⠀⠀⠀
⠀⡠⠂⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠈⠁⠂⢄
⢰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀ ⠈ 
             By Sanosec"""


class clr:
    BLACK   = '\033[30m'
    RED     = '\033[31m'
    GREEN   = '\033[32m'
    YELLOW  = '\033[33m'
    BLUE    = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN    = '\033[36m'
    WHITE   = '\033[37m'
    RESET   = '\033[0;0;0m'
    BOLD    = '\033[1m'

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"{clr.RED}Rapido e indiscreto Scanner de portas por Sano :P{clr.RESET}"
    )
    parser.add_argument('-t','--target', dest='host', required=True,
                        help='Target IP or domain')
    parser.add_argument('--timeout', dest='timeout', type=float, default=None,
                        help='Timeout em milisegundos por porta (default: auto via ping)')
    parser.add_argument('--threads', dest='threads', type=int, default=30, 
                        help='Numero de threads para utilizar (default: 30 threads)')
    parser.add_argument('-o', '--output', dest='output', default=None,
                        help='Arquivo que conterá as portas escaneadas (default: not save)')
    parser.add_argument('--more', dest='top10k', action='store_true',
                        help='Escanear top 10 mil portas em vez de top 1000')
    return parser.parse_args()

def get_timeout(host: str) -> float:
    try:
        result = ping(target=host, count=2, timeout=5)
        return float(result.rtt_avg_ms) + 80
    except KeyboardInterrupt:
        print(f"\n{clr.RED}[!]{clr.RESET} Operação cancelada pelo usuário\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{clr.RED}[!] FATAL-ERROR: {clr.RESET} {e}\n")
        sys.exit(1)


class PortScanner:
    
    def __init__(
        self,
        host: str,
        timeout_ms: float,
        num_threads: int,
        output: str | None,
        use_top10k: bool
        ):
        self.host = host
        self.timeout_ms = timeout_ms
        self.num_threads = num_threads
        self.output = output
        
        port_list = TOP10K if use_top10k else TOP1K
        self.port_queue: queue.Queue[int] = queue.Queue()
        for p in port_list:
            self.port_queue.put(p)
        
        self.result_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.open_ports: list[int] = []
        self.error: str | None = None
        self.stop_event = threading.Event()
    
    
    def run(self) -> list[int]:
        threads = [
            threading.Thread(target=self._worker, daemon=True)
            for _ in range(self.num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        if self.error:
            print(self.error)
            sys.exit(1)
        
        return sorted(self.open_ports)
    
    def _worker(self):
        while not self.stop_event.is_set():
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break
            self._probe(port)

    def _probe(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_ms / 1000)
                status = sock.connect_ex((self.host, port))
            
            if status == 0:
                self._register_open(port)
        except KeyboardInterrupt:
            self.stop_event.set()
            print(f"\n{clr.RED}[!]{clr.RESET} Operação cancelada pelo usuário\n")
            sys.exit(0)

        except socket.gaierror:
            self.stop_event.set()
            with self.result_lock:
                self.error = (
                    f'\n {clr.RED}[!]{clr.RESET} Por favor verifique o dominio - getaddrinfo falhou\n'
                )
        except OSError:
            pass

    def _register_open(self, port: int):
        print(f"{clr.BOLD}{clr.GREEN}[+]{clr.RESET} {clr.CYAN}{port:<5}{clr.RESET} -> Open")

        with self.result_lock:
            self.open_ports.append(port)

        if self.output:
            with self.file_lock:
                with open(self.output, 'a') as fh:
                    fh.write(f'{port}\n')


def main():
    print(arte_ascii)
    start = time.time()
    args = parse_args()

    print(f'\n {clr.YELLOW} [PINGING ON DOMAIN...]{clr.RESET}')
    timeout_ms = args.timeout if args.timeout else get_timeout(args.host)

    print(f'Domain = {clr.MAGENTA}{args.host}{clr.RESET}')
    print(f'Timeout = {clr.MAGENTA}{timeout_ms:.2f}{clr.RESET} ms')
    print(f'Threads = {clr.MAGENTA}{args.threads}{clr.RESET}')
    print(f'\n{clr.YELLOW} [  Resultados  ]{clr.RESET}')

    scanner = PortScanner(
        host=args.host,
        timeout_ms=timeout_ms,
        num_threads=args.threads,
        output=args.output,
        use_top10k=args.top10k
    )
    open_ports = scanner.run()

    elapsed = time.time() - start
    port_count = '10000' if args.top10k else '1000'

    print(f'\n {clr.BOLD}{clr.GREEN}[#]{clr.RESET} {clr.MAGENTA}{len(open_ports)}{clr.RESET} Portas abertas')
    print(f'\n{clr.BOLD}{clr.YELLOW}[i]{clr.RESET} {clr.MAGENTA}{port_count}{clr.RESET} Portas escaneadas')
    if args.output:
        print(f'\n {clr.BOLD}{clr.GREEN}[#]{clr.RESET} Exportado para {clr.CYAN}{args.output}')
    print(f'\n{clr.BOLD}{clr.YELLOW}[i]{clr.RESET} Tempo de execução: {elapsed:,.3f} segundos\n')


if __name__ == '__main__':
    main()
