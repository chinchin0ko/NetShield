"""Application entry point: compose the HTTP adapter."""
from fastapi import FastAPI

from app.interfaces.http import router

app = FastAPI(title="NetShield API", version="0.1.0")
app.include_router(router)
