from typing import Literal

from pydantic import BaseModel


class IncorrectEmailOrPassword(BaseModel):
    detail: Literal['Incorrect email or password']


class EmailAlreadyExists(BaseModel):
    detail: Literal['User with this email already exists']


class IncorrectToken(BaseModel):
    detail: Literal['Incorrect token']
