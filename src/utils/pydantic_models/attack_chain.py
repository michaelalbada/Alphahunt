from typing import List, Dict
from pydantic import BaseModel, model_validator
from .qa import QuestionAnswerPair

class AttackChain(BaseModel):
    id: str
    name: str
    description: str
    steps: List[Dict[str, dict]]  # Each dict: {step_file: str, parameters: dict}
    qas: List[QuestionAnswerPair] = []

    @model_validator(mode="after")
    def check_steps_and_qas(cls, values):
        steps = values.get('steps', [])
        qas = values.get('qas', [])
        # Ensure all step_files are non-empty
        for step in steps:
            if not step.get('step_file'):
                raise ValueError("Each step must have a step_file.")
        # Ensure Q&A IDs are unique
        qa_ids = [qa.id for qa in qas]
        if len(qa_ids) != len(set(qa_ids)):
            raise ValueError("Q&A IDs must be unique.")
        return values 