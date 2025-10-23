from collections import defaultdict
from pathlib import Path
import json
import polars as pl
from typing import Dict, Callable

DATA_FOLDERS = [
    "benign_data","reconnaissance","initial_access","exfiltration",
    "credential_access","impact","command_and_control",
    "execution","lateral_movement","collection","persistence","combined"
]

_TS_CANDIDATES = ["Timestamp","TimeGenerated","event_time",
                  "EventTime","time","timestamp"]

def setup_output_dirs(base: Path) -> Dict[str, Path]:
    """
    Return a dict {name: Path} for every logical sub-folder, but
    create *only* the scenario root.  The individual sub-folders will
    be created later by write_tables(), but only if data is written.
    """
    base.mkdir(parents=True, exist_ok=True)
    return {sub: base / sub for sub in DATA_FOLDERS}

def write_tables(tables: Dict[str, pl.DataFrame],
                 out_dir: Path,
                 sink: Callable[[str, pl.DataFrame], None] | None = None):
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, df in tables.items():
        df.write_csv(out_dir / f"{name}.csv")
        if sink:
            sink(name, df)

def normalise_ts(df: pl.DataFrame) -> pl.DataFrame:
    for c in _TS_CANDIDATES:
        if c in df.columns and c != "Timestamp":
            return df.rename({c: "Timestamp"})
    return df

def combine_and_save_qa(qa_frames: list, output_file: str, logger) -> None:
    logger.log_info("DEBUG: QA frames received for combination:")
    for i, frame in enumerate(qa_frames):
        logger.log_info(f"  Frame {i}: type={type(frame)}, value={frame}")
    all_qa_dicts = []
    for frame in qa_frames:
        if frame is None:
            continue
        # If frame is a DataFrame, convert to dicts
        if hasattr(frame, 'to_dicts'):
            frame_dicts = frame.to_dicts()
        # If frame is a list of dicts or models, use as is
        elif isinstance(frame, list):
            frame_dicts = []
            for item in frame:
                if hasattr(item, 'model_dump'):
                    frame_dicts.append(item.model_dump())
                else:
                    frame_dicts.append(item)
        else:
            continue
        all_qa_dicts.extend(frame_dicts)
    if not all_qa_dicts:
        logger.log_info("No valid QA dicts to combine")
        return
    logger.log_info("[DEBUG] all_qa_dicts before deduplication:")
    for d in all_qa_dicts:
        logger.log_info(d)
    # Deduplicate by (Question, AnswerType, AnswerValue)
    unique_rows = []
    seen = set()
    for row in all_qa_dicts:
        # Robust extraction
        q = row.get("Question") or row.get("question")
        a = row.get("Answer") or row.get("answer")
        # If answer is a dict with 'type' and 'value', extract
        if isinstance(a, dict) and "type" in a and "value" in a:
            answer_type = a["type"].value if hasattr(a["type"], "value") else str(a["type"])
            answer_value = a["value"]
        else:
            answer_type = type(a).__name__
            answer_value = a
        # PATCH: Try to convert answer_value to int or float if it's a string
        if isinstance(answer_value, str):
            try:
                int_val = int(answer_value)
                answer_value = int_val
                answer_type = "int"
            except ValueError:
                try:
                    float_val = float(answer_value)
                    answer_value = float_val
                    answer_type = "float"
                except ValueError:
                    pass
        elif isinstance(answer_value, int):
            answer_type = "int"
        elif isinstance(answer_value, float):
            answer_type = "float"
        # Get question string
        if isinstance(q, str):
            question_str = q
        elif isinstance(q, dict) and "question" in q:
            question_str = q["question"]
        else:
            question_str = str(q)
        key = (question_str, answer_type, json.dumps(answer_value, sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            unique_rows.append({
                "Question": question_str,
                "AnswerType": answer_type,
                "AnswerValue": answer_value
            })
    logger.log_info("[DEBUG] Unique QA rows to be exported:")
    for r in unique_rows:
        logger.log_info(r)
    # Write CSV: Question, Answer (answers as JSON if structured)
    def format_answer_for_csv(answer_value):
        if isinstance(answer_value, (list, dict)):
            return json.dumps(answer_value, ensure_ascii=False)
        return str(answer_value)
    csv_rows = []
    for row in unique_rows:
        answer_str = format_answer_for_csv(row["AnswerValue"])
        csv_rows.append({"Question": row["Question"], "Answer": answer_str})
    df = pl.DataFrame(csv_rows)
    df.write_csv(output_file)
    # Write JSON: list of objects with Question and Answer
    with open(output_file.replace('.csv', '.json'), 'w') as jf:
        json.dump(csv_rows, jf, indent=2, default=str)