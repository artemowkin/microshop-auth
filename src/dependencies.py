from fastapi import Security, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from .handlers import AuthHandler
from .services import DBAuth, SessionStorage, JWTManager
from .models import async_session, User
from .settings import settings


oauth2_scheme = HTTPBearer()


async def use_session() -> AsyncSession:
    """Creates an async sqlalchemy session"""
    async with async_session() as session:
        yield session
        await session.commit()


async def use_redis() -> Redis:
    """Returns redis connection"""
    return await Redis.from_url(settings.redis_url)


def use_db_auth(session: AsyncSession = Depends(use_session)) -> DBAuth:
    """Returns database authenticator"""
    return DBAuth(session)


def use_session_storage(redis_db: Redis = Depends(use_redis)) -> SessionStorage:
    """Returns session storage"""
    return SessionStorage(redis_db)


def use_jwt_manager() -> JWTManager:
    """Returns jwt manager"""
    return JWTManager(
        settings.secret_key,
        settings.access_token_expire_seconds,
        settings.refresh_token_expire_seconds
    )


def use_auth_handler(
    session: AsyncSession = Depends(use_session),
    db_auth: DBAuth = Depends(use_db_auth),
    session_storage: SessionStorage = Depends(use_session_storage),
    jwt_manager: JWTManager = Depends(use_jwt_manager),
) -> AuthHandler:
    """Returns authentication handler"""
    return AuthHandler(db_auth, session_storage, jwt_manager)


def use_token(credentials: HTTPAuthorizationCredentials = Security(oauth2_scheme)) -> str:
    """Returns token from request"""
    return credentials.credentials


async def auth_required(
    token: str = Depends(use_token),
    auth_handler: AuthHandler = Depends(use_auth_handler)
) -> User:
    """Returns user instance from request token"""
    user = await auth_handler.get_user_from_access_token(token)
    return user
