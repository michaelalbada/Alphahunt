import polars as pl
import os
import json
import yaml
from importlib import import_module
from pydantic import ValidationError

QA_CSV = 'alphahunt/qa_output.csv'
COMBINED_DIR = 'alphahunt/combined'
TRIVIAL_ANSWERS = {'Yes', 'No', 'N/A', 'Unknown', ''}
CRITICAL_EVENTS = ['aad_sign_in_events']

def normalize(val):
    if isinstance(val, str):
        return val.strip().lower()
    return val

def answer_in_data(answer, event_dfs, answer_field=None):
    # Try numeric match
    try:
        answer_num = float(answer)
        for df in event_dfs.values():
            cols = [answer_field] if answer_field and answer_field in df.columns else df.columns
            for col in cols:
                col_vals = df[col].to_list()
                matches = [x for x in col_vals if isinstance(x, (int, float, str)) and str(x).replace('.', '', 1).isdigit() and abs(float(x) - answer_num) < 1e-6]
                if matches:
                    if len(matches) > 1:
                        print(f'WARNING: Numeric answer {answer} matches multiple values in column {col}!')
                    return True
    except Exception:
        pass
    # Try set/list match
    if isinstance(answer, str) and ',' in answer:
        answer_set = set(normalize(x) for x in answer.split(','))
        for df in event_dfs.values():
            cols = [answer_field] if answer_field and answer_field in df.columns else df.columns
            for col in cols:
                for val in df[col].to_list():
                    if isinstance(val, str) and ',' in val:
                        val_set = set(normalize(x) for x in val.split(','))
                        if answer_set == val_set:
                            return True
    # Try substring/partial match
    for df in event_dfs.values():
        cols = [answer_field] if answer_field and answer_field in df.columns else df.columns
        for col in cols:
            col_vals = df[col].to_list()
            matches = [x for x in col_vals if normalize(str(answer)) in normalize(str(x)) or normalize(str(x)) in normalize(str(answer))]
            if matches:
                if len(matches) > 1:
                    print(f'WARNING: Answer "{answer}" matches multiple values in column {col}!')
                return True
    return False

def load_registry():
    return {}

def check_event_data_quality():
    for fname in os.listdir(COMBINED_DIR):
        if fname.endswith('.csv'):
            path = os.path.join(COMBINED_DIR, fname)
            try:
                df = pl.read_csv(path)
                if df.height == 0 or df.width == 0:
                    print(f'WARNING: {fname} is empty (rows: {df.height}, columns: {df.width})')
                if fname.replace('.csv', '') in CRITICAL_EVENTS and df.height < 10:
                    print(f'WARNING: {fname} has a small number of rows ({df.height})')
            except Exception as e:
                print(f'ERROR: Could not read {fname}: {e}')

def validate_event_data_against_schemas():
    # Map CSV file base names to Pydantic model class names
    SCHEMA_MAP = {
        'device_registry_events': 'DeviceRegistryEvents',
        'device_process_events': 'DeviceProcessEvents',
        'device_file_events': 'DeviceFileEvents',
        'device_network_events': 'DeviceNetworkEvents',
        'device_info': 'DeviceInfo',
        # Add more mappings as you add schemas
    }
    schema_module_base = 'src.utils.pydantic_models.defender_xdr'
    for fname in os.listdir(COMBINED_DIR):
        if fname.endswith('.csv'):
            base = fname.replace('.csv', '')
            if base in SCHEMA_MAP:
                model_name = SCHEMA_MAP[base]
                try:
                    mod = import_module(f'{schema_module_base}.{base}')
                    model = getattr(mod, model_name)
                except Exception as e:
                    print(f'WARNING: Could not import schema for {base}: {e}')
                    continue
                path = os.path.join(COMBINED_DIR, fname)
                df = pl.read_csv(path)
                errors = 0
                for i, row in enumerate(df.to_dicts()):
                    try:
                        model(**row)
                    except ValidationError as ve:
                        if errors < 5:
                            print(f'VALIDATION ERROR in {fname} row {i}: {ve}')
                        errors += 1
                if errors == 0:
                    print(f'[OK] {fname} validated against {model_name}')
                else:
                    print(f'[FAIL] {fname}: {errors} rows failed {model_name} validation')

def main():
    check_event_data_quality()
    validate_event_data_against_schemas()
    qa_df = pl.read_csv(QA_CSV)
    event_dfs = {}
    for fname in os.listdir(COMBINED_DIR):
        if fname.endswith('.csv'):
            df_name = fname.replace('.csv', '')
            event_dfs[df_name] = pl.read_csv(os.path.join(COMBINED_DIR, fname))
    registry_funcs = load_registry()
    trivial_count = 0
    for row in qa_df.iter_rows(named=True):
        question = row.get('Question')
        answer = row.get('Answer')
        answer_field = row.get('AnswerField') or row.get('answer_field')
        try:
            answer_obj = json.loads(answer)
        except Exception:
            answer_obj = answer
        if isinstance(answer_obj, dict) and answer_obj.get('type') == 'toolcall':
            func_name = answer_obj.get('function_name')
            lang = answer_obj.get('language')
            print(f'TOOLCALL: {question} => {answer_obj}')
            # Use validate_tool_calls.py for implementation check
            if func_name not in registry_funcs:
                print(f'WARNING: Tool call function "{func_name}" for question "{question}" not found in registry.yaml!')
            else:
                reg_lang = registry_funcs[func_name].get('language')
                if reg_lang != 'both' and lang != reg_lang:
                    print(f'WARNING: Tool call function "{func_name}" for question "{question}" not implemented for language "{lang}"! (Registry: {reg_lang})')
        else:
            if answer not in TRIVIAL_ANSWERS:
                if not answer_in_data(answer, event_dfs, answer_field=answer_field):
                    print(f'WARNING: Answer "{answer}" for question "{question}" not found in any event data!')
            else:
                trivial_count += 1
    if trivial_count == len(qa_df):
        print('WARNING: All answers are trivial (e.g., "Yes", "No", "N/A", "Unknown").')
    print(f"Checked {len(qa_df)} QA pairs. Trivial answers: {trivial_count}.")

if __name__ == '__main__':
    main() 