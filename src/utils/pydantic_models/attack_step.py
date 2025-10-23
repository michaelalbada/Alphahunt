from typing import List, Dict
from pydantic import BaseModel
from .qa import QuestionAnswerPair

class AttackStep(BaseModel):
    id: str
    name: str
    mitre_id: str
    description: str
    default_parameters: Dict[str, str]
    qas: List[QuestionAnswerPair] = [] 