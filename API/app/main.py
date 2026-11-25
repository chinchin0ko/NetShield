"""Application entry point: compose the HTTP adapter."""
from fastapi import FastAPI

from app.interfaces.http import router
from app.infrastructure.public_limit import PublicLimit

app = FastAPI(title="NetShield API", version="0.1.0")
app.add_middleware(PublicLimit)
app.include_router(router)
