import os, gc, re, ast, math, json, csv
from pathlib import Path
from typing import List

import torch
from unsloth import FastLanguageModel, is_bfloat16_supported
from datasets import Dataset
from trl import GRPOConfig, GRPOTrainer
import duckdb, glob, pathlib, polars as pl
from Levenshtein import distance

os.environ["UNSLOTH_VLLM_RETRY"] = "0"
os.environ["TORCHINDUCTOR_DISABLE_ASYNC_COMPILE"] = "1"
os.environ["TORCHINDUCTOR_CLEAR_CACHE"] = "1"

torch.cuda.empty_cache()
gc.collect()

MAX_SEQ_LEN  = 512
LORA_RANK    = 16

model, tokenizer = FastLanguageModel.from_pretrained(
    "unsloth/phi-4-bnb-4bit",
    fast_inference          = True,
    load_in_4bit            = True,
    gpu_memory_utilization  = 0.90,
    max_num_seqs            = 32,
    max_num_batched_tokens  = 32*(256+200),
)

model = FastLanguageModel.get_peft_model(
    model,
    r                         = LORA_RANK,
    target_modules            = ["gate_proj", "up_proj", "down_proj"],
    lora_alpha                = LORA_RANK,
    use_gradient_checkpointing= "unsloth",
    random_state              = 3407,
)

SYSTEM_PROMPT = """
You are an incident-response assistant.  For each question, think,
write ONE DuckDB SQL query that answers it, then produce the scalar
result.  Use format

<reasoning>
```sql
SELECT …;
```
</reasoning>
<answer>
<scalar value>
</answer>
"""

def make_prompt(question: str):
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": question},
    ]

XML_ANSWER_RE = re.compile(r"<answer>\s*(.*?)\s*</answer>", re.I|re.S)
def extract_xml_answer(text: str) -> str:
    m = XML_ANSWER_RE.search(text)
    return m.group(1).strip() if m else text.strip()

# ----------------------------------------------------------------
# 3.  Load AlphaHunt CSV  ->  HF Dataset
# ----------------------------------------------------------------
QA_CSV = Path("./output_data/alphahunt_chain_1/qa_output.csv")
if not QA_CSV.exists():
    raise FileNotFoundError("Place qa_output.csv next to this script!")

questions, answers = [], []
with QA_CSV.open(newline="") as fh:
    for row in csv.DictReader(fh):
        questions.append(row["Question"])
        answers.append(row["Answer"].strip())

# Duplicate the tiny dataset a few times so GRPO sees enough steps
_REPEAT = 200   # 38 × 200 = 7600 examples
data = {
    "prompt" : [make_prompt(q) for q in questions]*_REPEAT,
    "answer" : answers*_REPEAT,
}
dataset = Dataset.from_dict(data)



import duckdb, glob, pathlib, polars as pl

con = duckdb.connect(database=':memory:', read_only=False)

for csv_path in glob.glob(str("./output_data/alphahunt_chain_1/combined/*.csv")):
    name = pathlib.Path(csv_path).stem       # device_info, ...
    con.execute(
        f"CREATE VIEW {name} AS SELECT * FROM read_csv_auto('{csv_path}', HEADER=TRUE);"
    )

def run_sql(sql: str):
    """Return first column / first row or raise."""
    try:
        res = con.execute(sql).fetchall()
        if not res:
            raise ValueError("empty result")
        cell = res[0][0]
        # Convert DuckDB types to plain Python scalars
        if isinstance(cell, pl.Series):
            cell = cell.to_list()[0]
        return str(cell).strip()
    except Exception as e:
        # invalid SQL, table not found, etc.
        return f"__SQL_ERROR__: {e}"

# ----------------------------------------------------------------
# 4.  Reward helpers  (generic exact-match + format bonuses)
# ----------------------------------------------------------------
def _maybe_number(x: str):
    try:
        if x.endswith("%"): return float(x[:-1])
        if x.endswith("s"): return float(x[:-1])
        return float(x) if "." in x else int(x)
    except Exception: return None

def _normalise(x: str):
    x = x.strip().strip('"\'')
    if not x: return x
    if x.startswith(("[","(")):
        try:
            return {s.strip().lower() for s in ast.literal_eval(x)}
        except Exception: pass
    if "," in x and " " not in x:
        return {s.strip().lower() for s in x.split(",")}
    n = _maybe_number(x)
    if n is not None: return n
    return x.lower()

def score_exact(pred: str, gold: str) -> float:
    p, g = _normalise(pred), _normalise(gold)
    if isinstance(p,(int,float)) and isinstance(g,(int,float)):
        return float(abs(p-g) < 1e-3)
    if isinstance(p,set) and isinstance(g,set):
        return float(p==g)
    if isinstance(p,str) and isinstance(g,str):
        return float(p==g or distance(p,g)<=2)
    return 0.0

import re
SQL_BLOCK = re.compile(r"```sql\s*(.*?)\s*```", re.S|re.I)

def sql_accuracy_reward(prompts, completions, answer, **kw):
    out = []
    for comp, gold in zip(completions, answer):
        txt  = comp[0]["content"]
        print(txt)
        print(answer)
        sqlm = SQL_BLOCK.search(txt)
        if not sqlm:
            out.append(0.0)                    # no query → zero
            continue

        sql = sqlm.group(1)
        obtained = run_sql(sql)                # executes DuckDB
        gold     = str(gold).strip()

        score = 1.0 if obtained == gold else 0.0
        out.append(score * 2.0)                # weight=2
    return out

# 4b. simple structural rewards =============================================
def xmlcount(text):
    out=0.0
    out += 0.25 if "<reasoning>" in text else 0.0
    out += 0.25 if "</reasoning>" in text else 0.0
    out += 0.25 if "<answer>"    in text else 0.0
    out += 0.25 if "</answer>"   in text else 0.0
    return out

def xmlcount_reward_func(completions, **kw):
    return [xmlcount(c[0]["content"]) for c in completions]

def soft_format_reward_func(completions, **kw):
    pat = re.compile(r"<reasoning>.*?</reasoning>\s*<answer>.*?</answer>", re.S)
    return [0.5 if pat.search(c[0]["content"]) else 0.0 for c in completions]

# ----------------------------------------------------------------
# 5.  GRPO config
# ----------------------------------------------------------------
training_args = GRPOConfig(
    use_vllm                 = True,
    learning_rate            = 5e-6,
    adam_beta1               = 0.9,
    adam_beta2               = 0.99,
    weight_decay             = 0.1,
    warmup_ratio             = 0.1,
    lr_scheduler_type        = "cosine",
    optim                    = "paged_adamw_8bit",
    logging_steps            = 1,
    bf16                     = is_bfloat16_supported(),
    fp16                     = not is_bfloat16_supported(),
    per_device_train_batch_size = 2,
    gradient_accumulation_steps = 1,
    num_generations          = 2,
    max_prompt_length        = 256,
    max_completion_length    = 200,
    max_steps                = 400,
    save_steps               = 250,
    max_grad_norm            = 0.1,
    report_to                = "none",
    output_dir               = "outputs_alphahunt",
)


trainer = GRPOTrainer(
    model            = model,
    processing_class = tokenizer,
    train_dataset    = dataset,
    reward_funcs     = [
        xmlcount_reward_func,
        soft_format_reward_func,
        sql_accuracy_reward,
    ],
    args             = training_args,
)

if __name__ == "__main__":
    trainer.train()