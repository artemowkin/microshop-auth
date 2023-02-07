import datetime
from uuid import uuid4

from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from sqlalchemy.types import UUID, String
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from .settings import settings


engine = create_async_engine(settings.database_url)

async_session = async_sessionmaker(engine)


class Base(DeclarativeBase):
    ...


class User(Base):
    __tablename__ = 'users'

    uuid = mapped_column(UUID, primary_key=True, default=uuid4)
    first_name: Mapped[str] = mapped_column(String(length=100))
    last_name: Mapped[str] = mapped_column(String(length=100))
    middle_name: Mapped[str | None] = mapped_column(String(length=100), nullable=True)
    registration_datetime: Mapped[datetime.datetime] = mapped_column(server_default=func.now())
    photo_url: Mapped[str] = mapped_column(String(length=500))
    is_stuff: Mapped[bool] = mapped_column(default=False)
    is_admin: Mapped[bool] = mapped_column(default=False)
