"""Terminal interface for CertWatch's shared TLS observability engine."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from api.index import inspect_domain_async

app = typer.Typer(add_completion=False, help="Concurrent TLS certificate and HTTPS observability.")
console = Console()
GRADE_STYLE = {"A+": "bold white", "A": "white", "B": "bright_black", "C": "bold grey70", "F": "bold white"}


async def inspect_all(domains: list[str]) -> list[dict[str, object]]:
    return list(await asyncio.gather(*(inspect_domain_async(domain) for domain in domains)))


@app.command()
def scan(domains: Annotated[list[str], typer.Argument(help="One or more hostnames or HTTPS URLs to inspect.")]) -> None:
    """Scan domains concurrently and print grade, latency, expiry, and TLS version."""
    results = asyncio.run(inspect_all(domains))
    table = Table(title="CertWatch TLS Observability", header_style="bold white", border_style="bright_black")
    table.add_column("Domain", style="bold")
    table.add_column("Grade", justify="center")
    table.add_column("Latency", justify="right")
    table.add_column("Days left", justify="right")
    table.add_column("TLS version")
    for result in results:
        grade = result["security_grade"]
        total_ms = result["latency"].get("total_ms")
        latency = f"{total_ms:.1f} ms" if isinstance(total_ms, (float, int)) else "—"
        table.add_row(result["domain"], f"[{GRADE_STYLE.get(grade, 'white')}]{grade}[/]", latency,
                      str(result["days_remaining"] if result["days_remaining"] is not None else "—"),
                      result["tls_version"] or "—")
    console.print(table)


if __name__ == "__main__":
    app()
