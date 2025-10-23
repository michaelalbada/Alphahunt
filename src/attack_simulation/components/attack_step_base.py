from abc import ABC, abstractmethod
from faker import Faker
from pydantic import BaseModel, ValidationError
import polars as pl
from typing import Any, List
from datetime import datetime
import os
from src.utils.pydantic_models.qa import QuestionAnswerPair
import json
from src.utils.logging_utils import BaseLogger
from src.utils.pydantic_helpers import build_dataframe_from_schema, auto_column_map
import yaml
import inspect

"""
AttackStepBase: Abstract base class for all attack chain step implementations.
Provides a standard interface for attack data generation, QA, and validation.
"""

class AttackStepConfig(BaseModel):
    benign_data: dict
    victims: list
    attacker: dict
    last_scan_time: datetime  # Accepts ISO string or datetime, Pydantic will parse
    # Add other fields as needed
    class Config:
        extra = "allow"

class AttackStepBase(ABC, BaseLogger):
    def __init__(self, config: dict, debug: bool = False):
        """
        config: dict containing all needed values for the attack step.
        Required keys: 'benign_data', 'victims', 'attacker', 'last_scan_time', etc.
        """
        try:
            self.config = AttackStepConfig(**config)
        except ValidationError as e:
            raise ValueError(f"Invalid config for {self.__class__.__name__}: {e}")
        self.fake = Faker()
        self.data = None
        self.debug = debug
        BaseLogger.__init__(self)

    @property
    @abstractmethod
    def XDR_MODEL_MAP(self):
        """
        Subclasses must define this property as a dict {output_name: PydanticModel}
        """
        pass

    @property
    @abstractmethod
    def ANSWER_FUNCTIONS(self):
        """
        Subclasses must define this property as a mapping from question id to {"question": str, "func": callable}
        """
        pass

    @property
    @abstractmethod
    def DEFAULT_QA_YAML_PATH(self):
        """
        Subclasses must define this property as the default QA YAML path for QA generation.
        """
        pass

    @staticmethod
    def build_event_from_pydantic_model(model_cls, **kwargs):
        """
        Build an event dictionary using the fields from the given Pydantic model class.
        Only fields defined in the model will be included.
        """
        field_names = list(getattr(model_cls, '__fields__', {}).keys())
        return {field: kwargs.get(field, None) for field in field_names}

    @abstractmethod
    def generate_attack(self) -> tuple[dict[str, pl.DataFrame], Any, Any]:
        """
        Generate attack data for this step.

        Returns:
            data (dict[str, pl.DataFrame]):
                Dictionary of generated attack event DataFrames (even if only one event type is present).
            updated_victims (Any):
                The set of victims after this attack step (may be filtered or modified).
            last_event_time (Any):
                The last event time in this step, to be used as the starting point for the next step.
        """
        pass

    def generate_question_answer_pairs(self):
        """
        Generate QA pairs using the step's tightly-coupled YAML file.
        Uses self.DEFAULT_QA_YAML_PATH, which must be defined by the subclass.
        """
        import yaml
        from src.utils.pydantic_models.qa import Question, Answer, QuestionAnswerPair, AnswerType
        qa_yaml_path = self.DEFAULT_QA_YAML_PATH
        with open(qa_yaml_path, "r") as f:
            qa_list = yaml.safe_load(f)
        pairs = []
        for entry in qa_list:
            q = Question.ensure_id(entry)
            qid = q.id
            answer_func_entry = self.ANSWER_FUNCTIONS.get(qid)
            if not answer_func_entry:
                self.log_warning(f"No answer function found for question id {qid}")
                continue
            func = answer_func_entry["func"]
            # Build the relevant tables dict
            tables = {}
            if "tables" in entry:
                for t in entry["tables"]:
                    if t in self.data:
                        tables[t] = self.data[t]
            elif "table" in entry:
                t = entry["table"]
                if t in self.data:
                    tables[t] = self.data[t]
            else:
                tables = self.data
            # Always pass tables dict
            answer = func(tables)
            if answer is None:
                # Omit this QA pair if answer is None
                continue
            a = Answer(value=answer, type=AnswerType.string)
            pairs.append(QuestionAnswerPair(question=q, answer=a))
        return pairs

    def check_field_diversity(self, events_df, field, min_unique=2):
        """Warn if the specified field in events_df does not have enough unique values."""
        if events_df is not None and field in events_df.columns:
            unique_count = events_df[field].n_unique()
            if unique_count < min_unique:
                self.log_warning(f"Field '{field}' has only {unique_count} unique value(s); answers may be trivially easy.")
            return unique_count
        return 0

    def validate_qa_pairs(self, qa_pairs, events_df=None):
        """
        Validate that the output of generate_question_answer_pairs is a polars DataFrame of dicts
        or a list of QuestionAnswerPair objects. Also performs generic answer validation.
        """
        import polars as pl
        from src.utils.pydantic_models.qa import QuestionAnswerPair

        # Accept both DataFrame and list of QuestionAnswerPair
        if isinstance(qa_pairs, pl.DataFrame):
            qa_records = qa_pairs.to_dicts()
        elif isinstance(qa_pairs, list) and all(isinstance(q, QuestionAnswerPair) for q in qa_pairs):
            qa_records = [q.model_dump() for q in qa_pairs]
        else:
            raise TypeError("generate_question_answer_pairs() must return a polars DataFrame or a list of QuestionAnswerPair objects")

        answer_values = []
        questions_seen = set()
        expected_fields = {"question", "answer", "metadata"}
        MIN_Q_LEN, MAX_Q_LEN = 10, 300
        MIN_A_LEN, MAX_A_LEN = 1, 200
        # --- Enhanced validation ---
        for record in qa_records:
            # Duplicate question check
            q = record.get("question", {})
            a = record.get("answer", {})
            question_text = q.get("question") if isinstance(q, dict) else getattr(q, "question", None)
            if question_text in questions_seen:
                self.log_warning(f"Duplicate question detected: '{question_text}'")
            questions_seen.add(question_text)
            # Question/answer length checks
            if isinstance(question_text, str):
                if len(question_text) < MIN_Q_LEN:
                    self.log_warning(f"Question too short: '{question_text}'")
                if len(question_text) > MAX_Q_LEN:
                    self.log_warning(f"Question too long: '{question_text[:50]}...'")
            answer_value = a.get("value") if isinstance(a, dict) else getattr(a, "value", None)
            if isinstance(answer_value, str):
                if len(answer_value) < MIN_A_LEN:
                    self.log_warning(f"Answer too short: '{answer_value}'")
                if len(answer_value) > MAX_A_LEN:
                    self.log_warning(f"Answer too long: '{answer_value[:50]}...'")
            # Missing/empty answer check
            if answer_value in [None, "", "N/A", "Unknown"]:
                self.log_warning(f"Missing or empty answer for question: '{question_text}'")
            # Answer type consistency check
            answer_type = a.get("type") if isinstance(a, dict) else getattr(a, "type", None)
            if answer_type == "int" and not isinstance(answer_value, int):
                try:
                    int(answer_value)
                except Exception:
                    self.log_warning(f"Answer type mismatch: expected int, got {type(answer_value)} for question '{question_text}'")
            if answer_type == "float" and not isinstance(answer_value, float):
                try:
                    float(answer_value)
                except Exception:
                    self.log_warning(f"Answer type mismatch: expected float, got {type(answer_value)} for question '{question_text}'")
            if answer_type == "str" and not isinstance(answer_value, str):
                self.log_warning(f"Answer type mismatch: expected str, got {type(answer_value)} for question '{question_text}'")
            answer_values.append(answer_value)
            # Triviality check (per answer)
            if answer_value == "Yes":
                self.log_warning(f"Answer for question '{question_text}' may be trivially easy (always 'Yes').")
            # Answer-in-DB check (if events_df provided)
            if events_df is not None and isinstance(answer_value, str) and answer_value not in [None, "Unknown", "N/A"]:
                # Flatten all values in the DataFrame to a list of strings
                flat_values = []
                for col in events_df.columns:
                    flat_values.extend([str(v) for v in events_df[col].to_list() if v is not None])
                matches = [x for x in flat_values if answer_value in x or x in answer_value]
                if not matches:
                    self.log_warning(f"Data-derived answer '{answer_value}' for question '{question_text}' not found in DataFrame!")
                elif len(matches) > 1:
                    self.log_warning(f"Ambiguous answer '{answer_value}' for question '{question_text}' matches multiple values in event data.")
            # Metadata consistency check
            if "metadata" in record and not isinstance(record["metadata"], dict):
                self.log_warning(f"Metadata is not a dict for question: '{question_text}'")
            # Unused/unexpected fields check
            extra_fields = set(record.keys()) - expected_fields
            if extra_fields:
                self.log_warning(f"Unexpected fields in QA record: {extra_fields}")
        # Triviality check (all answers the same)
        if len(answer_values) > 1 and len(set(answer_values)) == 1:
            self.log_warning("All QA answers are the same value, may be trivially easy.")
        # --- Field diversity checks for common fields ---
        for field in ["RegistryKey", "ExeName"]:
            self.check_field_diversity(events_df, field)
        return True

    def validate_data(self):
        """
        Validate the generated data (e.g., using Pydantic models and additional semantic checks).
        Returns:
            validation_report (dict or bool): Validation results.
        """
        import polars as pl
        from datetime import datetime
        if not hasattr(self, 'data') or self.data is None:
            return {"error": "No data to validate."}
        from pydantic import TypeAdapter
        try:
            for name, df in self.data.items():
                model = self.XDR_MODEL_MAP.get(name)
                if model is not None:
                    all_events = df.to_dicts()
                    TypeAdapter(list[model]).validate_python(all_events)
                # --- Additional semantic checks (Polars only) ---
                # 1. Value range checks (timestamps, sizes)
                if "Timestamp" in df.columns:
                    now = datetime.now().timestamp()
                    future_rows = df.filter(pl.col("Timestamp").cast(pl.Float64) > now)
                    if future_rows.height > 0:
                        self.log_warning(f"Some timestamps in {name} are in the future.")
                for col in df.columns:
                    if "size" in col.lower():
                        neg_rows = df.filter(pl.col(col) < 0)
                        if neg_rows.height > 0:
                            self.log_warning(f"Negative values in size field '{col}' in {name}.")
                        large_rows = df.filter(pl.col(col) > 1e12)
                        if large_rows.height > 0:
                            self.log_warning(f"Extremely large values in size field '{col}' in {name}.")
                # 2. Uniqueness/Primary Key checks
                for id_col in ["EventID", "Id", "event_id", "id"]:
                    if id_col in df.columns:
                        if df[id_col].n_unique() < df.height:
                            self.log_warning(f"Duplicate {id_col}s found in {name}.")
                # 3. Null/NaN/None checks for required fields
                required_fields = ["UserID", "Timestamp", "AccountUpn", "DeviceId"]
                for field in required_fields:
                    if field in df.columns and df[field].null_count() > 0:
                        self.log_warning(f"Null values found in required field '{field}' in {name}.")
                # 4. Categorical value checks
                categorical_fields = {"Status": {"Success", "Failure"}, "Action": {"Read", "Write", "Delete", "Create"}}
                for field, allowed in categorical_fields.items():
                    if field in df.columns:
                        unique_vals = set(df[field].unique())
                        if not unique_vals.issubset(allowed):
                            self.log_warning(f"Unexpected {field} values in {name}: {unique_vals - allowed}")
                # 5. Cross-field consistency
                if "Action" in df.columns and "FilePath" in df.columns:
                    mask = df.filter((pl.col("Action") == "Delete") & (pl.col("FilePath").is_null()))
                    if mask.height > 0:
                        self.log_warning(f"Delete actions with null FilePath in {name}.")
                # 6. Outlier detection (numeric fields, Polars only)
                for col in df.columns:
                    if pl.datatypes.is_numeric(df[col].dtype):
                        # Use quantile for IQR
                        q1 = df[col].quantile(0.25, interpolation="nearest")
                        q3 = df[col].quantile(0.75, interpolation="nearest")
                        iqr = q3 - q1
                        lower = q1 - 3 * iqr
                        upper = q3 + 3 * iqr
                        outliers = df.filter((pl.col(col) < lower) | (pl.col(col) > upper))
                        if outliers.height > 0:
                            self.log_warning(f"Outliers detected in numeric field '{col}' in {name}.")
                # 7. Cardinality checks
                for col in ["UserID", "AccountUpn", "DeviceId"]:
                    if col in df.columns and df[col].n_unique() == 1:
                        self.log_warning(f"Only one unique {col} in {name}.")
                # 8. Referential integrity (if possible)
                # (This requires access to reference data, so just a placeholder)
                # 9. Temporal consistency
                if "StartTime" in df.columns and "EndTime" in df.columns:
                    mask = df.filter(pl.col("EndTime") < pl.col("StartTime"))
                    if mask.height > 0:
                        self.log_warning(f"EndTime before StartTime in {name}.")
                # 10. Duplicate row detection
                if df.n_unique() < df.height:
                    self.log_warning(f"Duplicate rows found in {name}.")
            return True
        except Exception as e:
            return {"error": str(e)}

    def export_data(self, output_dir):
        """
        Validate all generated data with Pydantic and export to CSV if valid.
        """
        validation = self.validate_data()
        if validation is not True:
            raise ValueError(f"Validation failed: {validation}")
        if not hasattr(self, 'data') or self.data is None:
            raise ValueError("No data to export.")
        os.makedirs(output_dir, exist_ok=True)
        for name, df in self.data.items():
            df.write_csv(os.path.join(output_dir, f"{name}.csv"))

    def export_qa_pairs(self, qa_pairs, output_path: str, format: str = "csv"):
        """
        Validate and export QA pairs to the specified file.
        Args:
            qa_pairs: List[QuestionAnswerPair]
            output_path: Path to save the exported file
            format: "csv" or "json"
        """
        self.validate_qa_pairs(qa_pairs)
        import polars as pl
        qa_dicts = [q.model_dump() for q in qa_pairs]
        # Serialize 'question' and 'answer' fields as JSON strings
        for q in qa_dicts:
            if 'question' in q:
                q['Question'] = json.dumps(q['question'], default=str)
            if 'answer' in q:
                q['Answer'] = json.dumps(q['answer'], default=str)
        # Use only the JSON-stringified columns for export
        df = pl.DataFrame([{k: v for k, v in q.items() if k in ['Question', 'Answer']} for q in qa_dicts])
        if format == "csv":
            df.write_csv(output_path)
        elif format == "json":
            df.write_json(output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def build_events_df(self, model_cls, n, victims_df, manual_overrides=None):
        """
        Build a schema-aligned Polars DataFrame for the given Pydantic model.
        Uses auto_column_map to map local *_col variables and applies manual_overrides for special fields.
        """
        schema_fields = list(model_cls.model_fields.keys())
        caller_locals = inspect.currentframe().f_back.f_locals
        column_map = auto_column_map(schema_fields, caller_locals, manual_overrides)
        return build_dataframe_from_schema(model_cls, column_map, n, victims_df)

    def build_answer_functions(self, yaml_path=None):
        if yaml_path is None:
            yaml_path = self.DEFAULT_QA_YAML_PATH
        mapping = {}
        with open(yaml_path, "r") as f:
            qa_list = yaml.safe_load(f)
        for entry in qa_list:
            qid = entry["id"]
            func_name = f"answer_{qid.replace('-', '_')}"
            func = getattr(self, func_name, None)
            if func:
                mapping[qid] = {"question": entry["question"], "func": func}
            else:
                self.log_warning(f"No answer function found for question id {qid} (expected function name: {func_name})")
        return mapping

    def _get_table(self, tables, table_name):
        df = tables.get(table_name)
        if df is None or df.height == 0:
            return None
        return df

    def _check_column(self, df, column, expected_type=None):
        if column not in df.columns:
            self.log_warning(f"Column '{column}' not found in DataFrame.")
            return False
        if expected_type and df[column].dtype != expected_type:
            self.log_warning(f"Column '{column}' is not of type {expected_type}.")
            return False
        return True

    def _most_common_value(self, df, column):
        counts = df[column].value_counts()
        if counts.height == 0:
            return None
        top_count = counts[0, "count"]
        tied = counts.filter(pl.col("count") == top_count)
        if tied.height > 1:
            self.log_warning(f"Ambiguous result: multiple values are equally most common for column {column}.")
        return counts[0, column]

    def _unique_count(self, df, column):
        if df[column].null_count() > 0:
            self.log_warning(f"{column} column contains null values.")
        return str(df[column].n_unique())

    def _time_frame(self, df, column="Timestamp"):
        if df[column].null_count() > 0:
            self.log_warning(f"{column} column contains null values.")
        min_time = df[column].min()
        max_time = df[column].max()
        if min_time is not None and max_time is not None:
            return str(max_time - min_time)
        return None