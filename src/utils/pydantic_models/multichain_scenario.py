from typing import List
from pydantic import BaseModel
from .qa import QuestionAnswerPair

class MultiChainScenario(BaseModel):
    id: str
    name: str
    description: str
    chains: List[str]  # Filenames of chains
    qas: List[QuestionAnswerPair] = [] 