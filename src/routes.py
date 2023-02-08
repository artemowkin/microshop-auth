import datetime

from fastapi import APIRouter, Body, status

from .schemas import TokenPair, LoginData, RegistrationData, UserOut
from .responses import IncorrectEmailOrPassword, EmailAlreadyExists, IncorrectToken


router = APIRouter()


@router.post(
    '/login/',
    response_model=TokenPair,
    responses={
        status.HTTP_200_OK: {
            "model": TokenPair,
            "description": "User has logged in. Returns access and refresh tokens"
        },
        status.HTTP_400_BAD_REQUEST: {
            "model": IncorrectEmailOrPassword,
            "description": "Incorrect data was sent"
        },
    },
)
async def login(data: LoginData):
    """Log in user using email and password from json body"""
    return TokenPair(access_token='sdfsdfsd', refresh_token='sdfsdfsd')


@router.post(
    '/registration',
    response_model=TokenPair,
    responses={
        status.HTTP_200_OK: {
            "model": TokenPair,
            "description": "User has registrated. Returns access and refresh tokens"
        },
        status.HTTP_409_CONFLICT: {
            "model": EmailAlreadyExists,
            "description": "Returning when user with this email already exists"
        }
    },
)
async def registration(data: RegistrationData):
    """Registrate new user with email and password"""
    return TokenPair(access_token='sdfsdfsd', refresh_token='sdfsdfsd')


@router.post(
    '/refresh/',
    response_model=TokenPair,
    responses={
        status.HTTP_200_OK: {
            "model": TokenPair,
            "description": "Session refreshed. Returns new access token and refresh token"
        },
        status.HTTP_403_FORBIDDEN: {
            "model": IncorrectToken,
            "description": "Returning when token is invalid or expired"
        }
    }
)
async def refresh(refresh_token: str = Body(..., embed=True)):
    """Refresh access token for user"""
    return TokenPair(access_token='sdfsdfsd', refresh_token='sdfsdfsd')


@router.get(
    '/me/',
    response_model=UserOut,
    responses={
        status.HTTP_200_OK: {
            "model": UserOut,
            "description": "Returns current user binded with token from `Authorization` header"
        },
        status.HTTP_403_FORBIDDEN: {
            "model": IncorrectToken,
            "description": "Returning when token is invalid or expired"
        },
    }
)
async def me():
    """Returns current user for token"""
    return UserOut(
        first_name='ivan',
        last_name='ivanov',
        email='govno@gmail.com',
        registration_datetime=datetime.datetime(),
        is_stuff=False,
        is_admin=False
    )


@router.post(
    '/logout/',
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_204_NO_CONTENT: {
            "model": None,
            "description": "User was logged out",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": IncorrectToken,
            "description": "Returning when token is invalid or expired",
        },
    },
)
async def logout():
    """Removes user session (refresh token will not work)"""
    return
