from fastapi import APIRouter, Body, status, Depends

from .schemas import TokenPair, LoginData, RegistrationData, UserOut
from .responses import IncorrectEmailOrPassword, EmailAlreadyExists, IncorrectToken
from .handlers import AuthHandler
from .dependencies import use_auth_handler, auth_required, use_token
from .models import User


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
async def login(data: LoginData, auth_handler: AuthHandler = Depends(use_auth_handler)):
    """Log in user using email and password from json body"""
    token_pair = await auth_handler.login(data)
    return token_pair


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
async def registration(data: RegistrationData, auth_handler: AuthHandler = Depends(use_auth_handler)):
    """Registrate new user with email and password"""
    token_pair = await auth_handler.registrate(data)
    return token_pair


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
async def refresh(refresh_token: str = Body(..., embed=True), auth_handler: AuthHandler = Depends(use_auth_handler)):
    """Refresh access token for user"""
    token_pair = await auth_handler.refresh(refresh_token)
    return token_pair


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
async def me(user: User = Depends(auth_required)):
    """Returns current user for token"""
    return UserOut.from_orm(user)


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
async def logout(token: str = Depends(use_token), auth_handler: AuthHandler = Depends(use_auth_handler)):
    """Removes user session (refresh token will not work)"""
    await auth_handler.logout(token)
