from colorama import init, Fore, Style

init(autoreset=True)

class CLIColors:
    INFO = Fore.CYAN
    WARNING = Fore.YELLOW
    CRITICAL = Fore.RED + Style.BRIGHT
    SUCCESS = Fore.GREEN
    RESET = Style.RESET_ALL

    @staticmethod
    def print_info(msg):
        print(f"{CLIColors.INFO}[*]{CLIColors.RESET} {msg}")

    @staticmethod
    def print_warning(msg):
        print(f"{CLIColors.WARNING}[!]{CLIColors.RESET} {msg}")

    @staticmethod
    def print_critical(msg):
        print(f"{CLIColors.CRITICAL}[!!]{CLIColors.RESET} {msg}")

    @staticmethod
    def print_success(msg):
        print(f"{CLIColors.SUCCESS}[+]{CLIColors.RESET} {msg}")
