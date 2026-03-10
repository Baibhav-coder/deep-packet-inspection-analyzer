try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except:
    COLOR_ENABLED = False

    class Dummy:
        RED = GREEN = YELLOW = CYAN = BLUE = ""
        RESET_ALL = ""

    Fore = Style = Dummy()


def print_title(title):
    print("\n" + "=" * 70)
    print(title.center(70))
    print("=" * 70)


def print_section(title):
    print("\n" + title)
    print("-" * 70)


def print_table(headers, rows):

    if not rows:
        print("No data.")
        return

    col_widths = [len(h) for h in headers]

    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    def format_row(row):
        return " | ".join(
            str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)
        )

    print(format_row(headers))
    print("-+-".join("-" * w for w in col_widths))

    for row in rows:
        print(format_row(row))