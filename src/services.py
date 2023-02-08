from datetime import timedelta, datetime

from jose import JWTError, jwt
from fastapi import status, HTTPException
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert
from sqlalchemy.exc import NoResultFound

from .schemas import TokenPair, RegistrationData, UserOut
from .models import User


def _handle_not_found_error(raise_nomatch: bool = False):

    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except NoResultFound:
                if raise_nomatch:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, detail="This user doesn't exist")

                return None

        return wrapper

    return decorator


class JWTManager:
    """JWT tokens manager
    
    :param secret_key: JWT encoding/decoding secret
    :param access_exp: Expire timedelta for access token in seconds
    :param refresh_exp: Expire timedelta for refresh token in seconds
    :param algorithm: JWT encoding/decoding algorithm (`HS256` by default)
    """

    def __init__(self, secret_key: str, access_exp: int, refresh_exp: int, algorithm: str = 'HS256'):
        self._secret = secret_key
        self._alg = algorithm
        self._access_exp = access_exp
        self._refresh_exp = refresh_exp

    def _generate_token(self, data: str, expires_delta: timedelta) -> str:
        """Generates token for data
        
        :param data: Encoding data dict
        :param expires_delta: Token life time
        :returns: Generated token string
        """
        expire = datetime.utcnow() + expires_delta
        to_encode = {'exp': expire, 'sub': data}
        encoded_jwt = jwt.encode(to_encode, self._secret, algorithm=self._alg)
        return encoded_jwt

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None) -> str:
        """Generates access token for data
        
        :param data: Encoding data dict
        :param expires_delta: Access token life time, from constructor by default
        :returns: Generated token string
        """
        expires_delta = expires_delta if expires_delta else timedelta(seconds=self._access_exp)
        token = self._generate_token(data, expires_delta)
        return token

    def create_refresh_token(self, data: dict, expires_delta: timedelta | None = None) -> str:
        """Generates refresh token for data
        
        :param data: Encoding data dict
        :param expires_delta: Refresh token life time, from constructor by default
        :returns: Generated token string
        """
        expires_delta = expires_delta if expires_delta else timedelta(seconds=self._refresh_exp)
        token = self._generate_token(data, expires_delta)
        return token

    def decode_token(self, token: str) -> str:
        """Decodes token and returns decoded payload
        
        :param token: Token string
        :raises: HTTPException(403) if token is incorrect or expired
        :returns: Decoded token payload sub
        """
        credentials_exception = HTTPException(status.HTTP_403_FORBIDDEN, detail="Incorrect token")
        try:
            payload = jwt.decode(token, self._secret, algorithms=[self._alg])
            if not 'sub' in payload or not 'exp' in payload or payload['exp'] <= datetime.utcnow().timestamp():
                raise credentials_exception

            return payload['sub']
        except JWTError:
            raise credentials_exception


class SessionStorage:
    """Sessions storage using Redis
    
    :param redis_db: Redis connection instance
    """

    def __init__(self, redis_db: Redis):
        self._db = redis_db

    async def add(self, uuid: str, token_pair: TokenPair):
        """Creates new session for email and tokens pair
        
        :param uuid: User uuid that will be as identifier of user sessions
        """
        await self._db.hset(uuid, token_pair.refresh_token, token_pair.access_token)

    async def delete_by_access_token(self, uuid: str, token: str):
        """Deletes user session using access token
        
        :param uuid: User uuid (user sessions identifier)
        :param token: Access token
        """
        sessions = await self._db.hgetall(uuid)
        refresh_tokens = [refresh for refresh in sessions if sessions[refresh] == token.encode()]
        if not refresh_tokens: return
        await self._db.hdel(uuid, refresh_tokens[0].decode())

    async def clear_refresh_token_session(self, uuid: str, token: str):
        """Deletes user session using refresh token
        
        :param uuid: User uuid (user sessions identifier)
        :param token: Refresh token
        """
        await self._db.hdel(uuid, token)

    async def check_is_session_active(self, uuid: str, refresh_token: str) -> bool:
        """Checks is session active using refresh token
        
        :param uuid: User uuid (user sessions identifier)
        :param refresh_token: Refresh token
        """
        sessions = await self._db.hgetall(uuid)
        return refresh_token.encode() in sessions

    async def check_access_token(self, uuid: str, access_token: str) -> bool:
        """Checks is access token binded with session
        
        :param uuid: User uuid (user sessions identifier)
        :param access_token: Access token
        """
        sessions = await self._db.hgetall(uuid)
        current_sessions = [refresh for refresh in sessions if sessions[refresh] == access_token.encode()]
        return bool(current_sessions)


class DBAuth:
    """Database authentication manager
    
    :param session: SQLAlchemy async session
    """

    def __init__(self, session: AsyncSession):
        self._session = session

    @_handle_not_found_error(raise_nomatch=False)
    async def get_user_by_email(self, email: str) -> User | None:
        """Returns user by email
        
        :param email: User email
        :returns: Finded user or None
        """
        stmt = select(User).where(User.email == email)
        response = await self._session.execute(stmt)
        return response.scalar_one()

    @_handle_not_found_error(raise_nomatch=False)
    async def get_user_by_uuid(self, uuid: str) -> User | None:
        """Returns user by uuid
        
        :param uuid: User uuid
        :returns: Finded user or None
        """
        stmt = select(User).where(User.uuid == uuid)
        response = await self._session.execute(stmt)
        return response.scalar_one()

    async def create_user(self, registration_data: RegistrationData, hashed_password: str) -> User:
        """Creates new user using registration data and hashed password
        
        :param registration_data: Registration pydantic schema
        :param hashed_password: Hashed registration password
        """
        creation_data = registration_data.dict(exclude={'password1', 'password2'})
        stmt = insert(User).returning(User).values(**creation_data, password=hashed_password)
        response = await self._session.execute(stmt)
        return response.scalar_one()
