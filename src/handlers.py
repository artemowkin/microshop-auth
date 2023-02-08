from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
from passlib.context import CryptContext

from .services import DBAuth, SessionStorage, JWTManager
from .schemas import TokenPair, UserOut, LoginData, RegistrationData
from .models import User


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def _handle_unique_violation(func):

    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except IntegrityError:
            raise HTTPException(status.HTTP_409_CONFLICT, "User with this email already exists")

    return wrapper


class AuthHandler:
    """Authentication handler with user authentication logic
    
    :param session: SQLAlchemy async session
    :param db_auth: Database authentication manager
    :param session_storage: Session storage manager
    :param jwt_manager: JWT tokens manager
    """

    def __init__(
        self,
        db_auth: DBAuth,
        session_storage: SessionStorage,
        jwt_manager: JWTManager
    ):
        self._db_auth = db_auth
        self._session_storage = session_storage
        self._jwt_manager = jwt_manager

    def _generate_token_pair(self, user: User) -> TokenPair:
        """Generates access and refresh tokens for user
        
        :param user: Database user instance
        :returns: Generated access and refresh tokens
        """
        user_schema = UserOut.from_orm(user)
        access_token = self._jwt_manager.create_access_token(user_schema.json())
        refresh_token = self._jwt_manager.create_refresh_token(user_schema.json())
        return TokenPair(access_token=access_token, refresh_token=refresh_token)

    async def login(self, login_data: LoginData) -> TokenPair:
        """Login user using login data
        
        :param login data: Pydantic login data
        :raises: HTTPException(401) if email or password is incorrect
        :returns: Generated access and refresh tokens
        """
        db_user = await self._db_auth.get_user_by_email(login_data.email)
        if not db_user or not pwd_context.verify(login_data.password, db_user.password):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

        token_pair = self._generate_token_pair(db_user)
        await self._session_storage.add(str(db_user.uuid), token_pair)
        return token_pair

    @_handle_unique_violation
    async def registrate(self, registration_data: RegistrationData) -> TokenPair:
        """Registrate user using registration data
        
        :param registration_data: Pydantic registration data
        :returns: Generated access and refresh tokens for registrated user
        """
        hashed_password = pwd_context.hash(registration_data.password1)
        db_user = await self._db_auth.create_user(registration_data, hashed_password)
        token_pair = self._generate_token_pair(db_user)
        await self._session_storage.add(str(db_user.uuid), token_pair)
        return token_pair

    async def _get_user_from_token(self, token: str) -> User:
        """Returns user from token
        
        :param token: Token from request
        :raises: HTTPException(403) if token is incorrect
        :returns: User from token
        """
        sub_json = self._jwt_manager.decode_token(token)
        user = UserOut.parse_raw(sub_json)
        db_user = await self._db_auth.get_user_by_uuid(str(user.uuid))
        if not db_user:
            raise HTTPException(status.HTTP_403_FORBIDDEN, 'Incorrect token')

        return db_user

    async def get_user_from_access_token(self, token: str) -> User:
        """Returns user from access token
        
        :param token: Token from request
        :raises: HTTPException(403) if token is not in session
        :returns: User from token
        """
        db_user = await self._get_user_from_token(token)
        is_session_active = await self._session_storage.check_access_token(str(db_user.uuid), token)
        if not is_session_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, 'Incorrect token')

        return db_user

    async def _get_user_from_refresh_token(self, token: str) -> User:
        """Returns user from refresh token
        
        :param token: Token from request
        :raises: HTTPException(403) if token is not in session
        :returns: User from token
        """
        db_user = await self._get_user_from_token(token)
        is_session_active = await self._session_storage.check_is_session_active(str(db_user.uuid), token)
        if not is_session_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, 'Incorrect token')

        return db_user

    async def refresh(self, token: str) -> TokenPair:
        """Refresh access token for user
        
        :param token: Access token from request
        :returns: New access token and refresh token pair
        """
        db_user = await self._get_user_from_refresh_token(token)
        await self._session_storage.clear_refresh_token_session(str(db_user.uuid), token)
        user_schema = UserOut.from_orm(db_user)
        access_token = self._jwt_manager.create_access_token(user_schema.json())
        token_pair = TokenPair(access_token=access_token, refresh_token=token)
        await self._session_storage.add(str(db_user.uuid), token_pair)
        return token_pair

    async def logout(self, token: str) -> None:
        """Logout for user
        
        :param token: Access token from request
        """
        db_user = await self.get_user_from_access_token(token)
        await self._session_storage.delete_by_access_token(str(db_user.uuid), token)
