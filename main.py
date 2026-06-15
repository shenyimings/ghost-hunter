"""Ghost Hunter CLI entry point.

Usage
-----
  uv run main.py scan --parquet-dir parquets/v2 --output output/findings.jsonl
  uv run main.py scan --parquet-dir parquets/v2 parquets/v1 --max-concurrent 128
  uv run main.py scan --parquet-file parquets/v2/my_file --output output/test.jsonl
  uv run main.py scan --parquet-dir parquets/v2 --parquet-file extra/one_more

  # Resume an interrupted run — skips already-processed parquet files and
  # appends to the current JSONL chunk instead of truncating:
  uv run main.py scan --parquet-dir parquets/v2 --output output/findings.jsonl --resume
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


@cli.command()
@click.option(
    "--parquet-dir",
    "parquet_dirs",
    multiple=True,
    default=(),
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory containing parquet files (repeatable for multiple dirs).",
)
@click.option(
    "--parquet-file",
    "parquet_files",
    multiple=True,
    default=(),
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Single parquet file to scan (repeatable; combinable with --parquet-dir).",
)
@click.option(
    "--output",
    default="output/findings.jsonl",
    show_default=True,
    type=click.Path(path_type=Path),
    help=(
        "JSONL output file path. When max_output_mb > 0 (see config.yml) "
        "the stem is used as a prefix and actual files are named "
        "<stem>_000.jsonl, <stem>_001.jsonl, …"
    ),
)
@click.option(
    "--resume",
    is_flag=True,
    default=False,
    help=(
        "Resume an interrupted scan. Reads/writes a state file "
        "(<output-stem>.scan_state.json) in the output directory to track "
        "which parquet files have already been processed; skips them on "
        "restart and continues appending to the current JSONL chunk."
    ),
)
@click.pass_context
def scan(
    ctx: click.Context,
    parquet_dirs: tuple[Path, ...],
    parquet_files: tuple[Path, ...],
    output: Path,
    resume: bool,
) -> None:
    """Scan parquet files and classify each reverted matchOrders transaction.

    At least one of --parquet-dir or --parquet-file must be provided.
    """
    if not parquet_dirs and not parquet_files:
        raise click.UsageError("Provide at least one --parquet-dir or --parquet-file.")

    import sys
    sys.path.insert(0, str(Path(__file__).parent / "src"))

    from ghost_hunter.core.engine import Engine

    # Resolve the engine's parquet_root: first dir if any, else parent of first file.
    root = parquet_dirs[0] if parquet_dirs else parquet_files[0].parent
    engine = Engine(parquet_root=root, output_path=output, resume=resume)

    total = asyncio.run(
        engine.run(
            parquet_dirs=list(parquet_dirs),
            parquet_files=list(parquet_files),
        )
    )
    click.echo(f"Done — {total} findings written to {output}")


if __name__ == "__main__":
    cli()
