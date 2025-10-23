import os
import sys
from pathlib import Path
import argparse
from typing import Dict, Any
from datetime import datetime
import traceback
from glob import glob

from collections import defaultdict
import polars as pl
from dataclasses import dataclass
import inspect

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

import src.pipeline.stage_runners as stages
from src.utils.logging_utils import BaseLogger
from src.utils.config import load_config, validate_config, ConfigurationError
from src.utils.io import (
    setup_output_dirs, write_tables, combine_and_save_qa,
    normalise_ts, DATA_FOLDERS
)

Victim = Dict[str, Any]
Attacker = Dict[str, str]

UNIFIED_TABLES: defaultdict[str, list[pl.DataFrame]] = defaultdict(list)
DEBUG = False
logger = None

class GenerateDataLogger(BaseLogger):
    def __init__(self, debug=False):
        super().__init__(logger_name="GenerateData")
        self.debug = debug

def debug_print(*args, **kwargs):
    global logger
    if logger and getattr(logger, 'debug', False):
        logger.log_info(' '.join(str(a) for a in args))

def _collect_for_unified(name: str, df: pl.DataFrame):
    if df.is_empty():
        return

    df = normalise_ts(df)
    if UNIFIED_TABLES[name]:
        ref_cols = UNIFIED_TABLES[name][0].columns

        missing = [c for c in ref_cols if c not in df.columns]
        if missing:
            df = df.with_columns([pl.lit(None).alias(c) for c in missing])

        extra = set(df.columns) - set(ref_cols)
        if extra:
            df = df.drop(*extra)

        df = df.select(ref_cols)

    UNIFIED_TABLES[name].append(df)

def write_output_readme(base_dir):
    _TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
    _README_TEMPLATE = _TEMPLATE_DIR / "alphahunt_data_output_readme.md"
    txt = _README_TEMPLATE.read_text()
    (_TEMPLATE_DIR / "README.md").write_text(txt)
    with open(os.path.join(base_dir, "README.md"), "w") as f:
        f.write(txt)

attack_stage_functions = {
    "reconnaissance": stages.generate_reconnaissance,
    "initial_access": stages.generate_initial_access,
    "execution": stages.generate_execution,
    "credential_access": stages.generate_credential_access,
    "lateral_movement": stages.generate_lateral_movement,
    "collection": stages.generate_collection,
    "command_and_control": stages.generate_command_and_control,
    "exfiltration": stages.generate_exfiltration,
    "impact": stages.generate_impact,
    "persistence": stages.generate_persistence,
}

@dataclass
class StageCtx:
    victims: pl.DataFrame | None = None
    last_event_time: datetime | None = None

def generate_stage_data(stage: str,
                        func,
                        cfg: dict,
                        output_dir: Path,
                        ctx: StageCtx,
                        attacks_to_qa: dict,
                        benign_data,
                        attacker):
    """
    • Call the concrete stage generator
    • Persist its outputs
    • Update ctx and attacks_to_qa
    """

    if stage == "reconnaissance":
        data, ctx.victims, ctx.last_event_time, qa = func(
            benign_data, attacker, cfg
        )
    else:
        data, ctx.victims, ctx.last_event_time, qa = func(
            benign_data, attacker, ctx.victims, ctx.last_event_time, cfg
        )

    candidates: list[Any] = []
    if data:
        output_dir.mkdir(parents=True, exist_ok=True)
        write_tables(data, output_dir, sink=_collect_for_unified)

        candidates.append(data)
        if isinstance(data, dict):
            candidates.extend(data.values())

    generator_obj = inspect.currentframe().f_back.f_locals.get("generator")
    if generator_obj is not None:
        candidates.append(generator_obj)

    for obj in candidates:
        if hasattr(obj, "export_data"):
            obj.export_data(output_dir)

    # special case for persistence
    if stage == "persistence" and qa is not None:
        for obj in candidates:
            if hasattr(obj, "export_qa_pairs"):
                obj.export_qa_pairs(
                    qa, output_dir / "qa_pairs.csv", format="csv"
                )
                break

    attacks_to_qa[stage] = qa
    return attacks_to_qa

def _discover_config_files(cfg_arg: str | None) -> list[Path]:
    """
    If a single path is given, return [that_path]; otherwise crawl
    the ./config directory for all *.yml / *.yaml files.
    """
    if cfg_arg:
        return [Path(cfg_arg).resolve()]

    root = Path(__file__).resolve().parent.parent / "config"
    files = [Path(p) for p in glob(str(root / "**" / "*.yml"), recursive=True)]
    files += [Path(p) for p in glob(str(root / "**" / "*.yaml"), recursive=True)]
    if not files:
        raise FileNotFoundError(f"No YAML configs found under {root}")
    return sorted(files)

def run_attack_chain(
    attacks_cfg: dict,
    stage_dirs: dict,
    benign_data: Dict[str, pl.DataFrame],
    attacker: Dict[str, str],
    ctx: "StageCtx",
) -> dict[str, pl.DataFrame]:
    """
    Execute every configured attack stage, collect their QA frames
    and return a mapping {stage_name: qa_dataframe | None}.
    """
    attacks_to_qa: dict[str, pl.DataFrame] = {}

    for stage, stage_cfg in attacks_cfg.items():
        func = attack_stage_functions.get(stage)
        if func is None:
            logger.log_warning(f"Unknown stage '{stage}', skipping.")
            continue

        logger.log_info(f"\n[INFO] Running stage: {stage}")
        try:
            attacks_to_qa = generate_stage_data(
                stage,
                func,
                stage_cfg,
                stage_dirs.get(stage),
                ctx,
                attacks_to_qa,
                benign_data,
                attacker,
            )
        except Exception as exc:
            logger.log_error(f"{stage} failed: {exc}")
            logger.log_error(traceback.format_exc())
            continue

    return attacks_to_qa

def run_scenario(cfg_path: Path) -> None:
    """
    Runs the full benign + attack chain for a single YAML config file.
    Produces output_data/<scenario_name>/… and updates global UNIFIED_TABLES.
    """
    logger.log_info(f"\n===== Running scenario from {cfg_path.name} =====")

    try:
        config = load_config(cfg_path)
        validate_config(config)
    except Exception as e:
        logger.log_error(f"❌ Invalid config {cfg_path}: {e}")
        logger.log_error(traceback.format_exc())
        return

    scenario_name = cfg_path.stem
    base_output = Path("output_data") / scenario_name
    output_dirs = setup_output_dirs(base_output)
    write_output_readme(base_output)

    stage_dirs = {k: output_dirs[k] for k in DATA_FOLDERS if k in output_dirs}
    benign_data = stages.generate_benign_data(config.get("benign", {}))
    write_tables(benign_data, output_dirs["benign_data"], sink=_collect_for_unified)

    attacker = stages.generate_attacker()
    ctx = StageCtx()
    attacks_cfg = config.get("attacks", {})

    qa_by_stage = run_attack_chain(attacks_cfg, stage_dirs, benign_data, attacker, ctx)

    qa_frames = [df for df in qa_by_stage.values() if df is not None]
    qa_path = str(base_output / "qa_output.csv")
    combine_and_save_qa(qa_frames, qa_path, logger)

    combined_dir = output_dirs["combined"]
    combined_dir.mkdir(parents=True, exist_ok=True)
    for table, df_list in UNIFIED_TABLES.items():
        if not df_list:
            continue
        df = pl.concat(df_list, how="vertical_relaxed")
        if "Timestamp" in df.columns:
            df = df.sort("Timestamp")
        df.write_csv(combined_dir / f"{table}.csv")
        logger.log_info(f"[Unified] {table}: {df.shape[0]:,} rows")

    UNIFIED_TABLES.clear()

def main():
    global DEBUG, logger

    parser = argparse.ArgumentParser(
        description="Generate AlphaHunt benign + attack data.\n"
                    "If --config is omitted, every YAML in ./config is executed."
    )
    parser.add_argument("--config", help="Basename inside ./config or full path")
    parser.add_argument("--debug",  default=False, action="store_true", help="Verbose logging")
    args = parser.parse_args()

    DEBUG  = args.debug
    logger = GenerateDataLogger(debug=DEBUG)
    stages.logger = logger

    try:
        cfg_files = _discover_config_files(args.config)
    except Exception as e:
        logger.log_error(str(e))
        sys.exit(1)

    for cfg_path in cfg_files:
        run_scenario(cfg_path)

if __name__ == "__main__":
    main()
