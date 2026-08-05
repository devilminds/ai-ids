"""FastAPI application entry point for the AI-IDS backend."""
import logging
import os
import secrets

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine, SessionLocal
from .models import User
from .security import hash_password, decode_token
from .ws_manager import manager
from . import routes_auth, routes_traffic, routes_alerts, routes_predict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai-ids")

app = FastAPI(
    title="AI Intrusion Detection System",
    version="1.0.0",
    description="AI-powered network intrusion detection — API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_auth.router)
app.include_router(routes_traffic.router)
app.include_router(routes_alerts.router)
app.include_router(routes_predict.router)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

    # Seed a default admin account for first login. Username/password can be
    # set via ADMIN_USERNAME / ADMIN_PASSWORD env vars (do this when deploying
    # publicly). If ADMIN_PASSWORD isn't set, a random one is generated and
    # printed to the server logs ONCE — it is not recoverable after that, so
    # copy it down or set ADMIN_PASSWORD explicitly instead.
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.role == "admin").first():
            admin_username = os.getenv("ADMIN_USERNAME", "admin")
            admin_password = os.getenv("ADMIN_PASSWORD")
            generated = admin_password is None
            if generated:
                admin_password = secrets.token_urlsafe(12)

            admin = User(
                username=admin_username,
                email=f"{admin_username}@ai-ids.local",
                password_hash=hash_password(admin_password),
                role="admin",
            )
            db.add(admin)
            db.commit()

            if generated:
                logger.warning(
                    "=" * 60 + "\n"
                    f"No ADMIN_PASSWORD env var set — generated one for you.\n"
                    f"  username: {admin_username}\n"
                    f"  password: {admin_password}\n"
                    "This is shown ONLY here, ONCE. Save it now — log in and\n"
                    "change it, or set ADMIN_PASSWORD as an env var and\n"
                    "redeploy instead of relying on this generated one.\n" + "=" * 60
                )
            else:
                logger.info(f"Seeded admin user '{admin_username}' from ADMIN_PASSWORD env var")
    finally:
        db.close()

    from .ml.predict import model_is_ready
    if not model_is_ready():
        logger.warning("No trained ML model found — run `python -m app.ml.train` before using /api/predict")


@app.get("/", tags=["Root"])
def root():
    return {"message": "AI-IDS API is running", "docs": "/docs"}


@app.get("/health", tags=["Root"])
def health():
    return {"status": "healthy"}


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket, token: str = ""):
    """Real-time feed of new predictions/alerts. Browsers can't set custom
    headers on a WebSocket handshake, so auth goes via ?token=<jwt> instead
    of the usual Authorization header."""
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the client, but need to await
            # something so we notice a disconnect promptly.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

