from fastapi import FastAPI

from .routes import router
from .settings import settings
from .models import Base, engine


app = FastAPI(
    title='MicroShop',
    docs_url='/docs' if settings.environment == 'dev' else None,
    redoc_url='/redoc' if settings.environment == 'dev' else None
)

app.include_router(router, prefix='/api/v1', tags=['Authentication'])


@app.on_event('startup')
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
