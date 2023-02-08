import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, validator, UUID4


class BaseUser(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    middle_name: str | None = None
    photo_url: str | None = None
    email: EmailStr


class UserIn(BaseUser):
    ...


class UserOut(BaseUser):
    uuid: UUID
    registration_datetime: datetime.datetime
    is_stuff: bool
    is_admin: bool

    class Config:
        orm_mode = True


class LoginData(BaseModel):
    email: EmailStr
    password: str


class RegistrationData(BaseModel):
    email: EmailStr
    password1: str
    password2: str

    @validator('password2')
    def passwords_match(cls, v, values, **kwargs):
        if 'password1' in values and v != values['password1']:
            raise ValueError('passwords do not match')

        return v


class ProfileEditData(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    middle_name: str | None = None


class PasswordChangeData(BaseModel):
    old_password: str
    new_password1: str
    new_password2: str

    @validator('new_password2')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password1' in values and v != values['new_password1']:
            raise ValueError('passwords do not match')

        return v


class EmailChangeData(BaseModel):
    old_email: EmailStr
    new_email: EmailStr


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
