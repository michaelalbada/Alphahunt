from enum import Enum
from typing import Union, Optional
from pydantic import BaseModel, Field, validator
import uuid
import re
# from .qa import AnswerType

class AnswerType(str, Enum):
    string = 'string'
    timestamp = 'timestamp'
    toolcall = 'toolcall'

class Language(str, Enum):
    python = 'python'
    csharp = 'csharp'
    # Add more languages as needed

class ReturnType(str, Enum):
    string = 'string'
    integer = 'integer'
    float = 'float'
    bool = 'bool'
    object = 'object'
    # Add more return types as needed

class ToolCall(BaseModel):
    function_name: str
    arguments: dict
    language: Language
    return_type: ReturnType

class Answer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))  # required, auto-generated if not provided
    type: Optional[AnswerType] = None  # Now optional
    value: Union[str, int, float, ToolCall]
    # Optionally, you can add both python and csharp representations if needed

class Difficulty(str, Enum):
    easy = 'easy'
    medium = 'medium'
    hard = 'hard'

    @property
    def label(self):
        return self.value.capitalize()

class Scope(str, Enum):
    step = "step"
    chain = "chain"
    multi_chain = "multi_chain"
    alert = "alert"

class Question(BaseModel):
    id: str  # required
    question: str  # required
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    scope: Optional[Scope] = None
    answer_field: Optional[str] = None
    answer_type: Optional[AnswerType] = None
    qa_type: Optional[str] = None
    difficulty: Difficulty
    description: Optional[str] = None
    metadata: Optional[dict] = None
    # Add more fields as needed to match YAML schema

    @validator('mitre_technique')
    def validate_mitre_technique(cls, v):
        if v is not None and not re.match(r"^T\d{4}(\.\d{3})?$", v):
            raise ValueError("mitre_technique must be in the format T#### or T####.###")
        return v

    @classmethod
    def ensure_id(cls, data: dict):
        if 'id' not in data or not data['id']:
            data['id'] = str(uuid.uuid4())
        # Rename 'template' to 'question' if present
        if 'template' in data and 'question' not in data:
            data['question'] = data.pop('template')
        return cls(**data)

class QuestionAnswerPair(BaseModel):
    question: Question
    answer: Answer
    # Optionally, add metadata fields (e.g., scenario, step_id, etc.)
    metadata: Optional[dict] = None 