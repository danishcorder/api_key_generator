from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
import secrets, os

# ---------- Database Setup ----------
DATABASE_URL = "sqlite:///./apikeys.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    owner = Column(String)

Base.metadata.create_all(bind=engine)

# ---------- FastAPI App ----------
app = FastAPI()

# Serve static files (for frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_home():
    """Serve the frontend page"""
    return FileResponse("static/index.html")

# ---------- Generate API Key ----------
@app.post("/generate-key/")
async def generate_key(request: Request):
    data = await request.json()
    owner = data.get("owner")

    if not owner:
        raise HTTPException(status_code=400, detail="Owner name or email required")

    db = SessionLocal()
    new_key = secrets.token_hex(16)
    api_key = APIKey(key=new_key, owner=owner)
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    return {"owner": owner, "api_key": new_key}

# ---------- Protected Endpoint ----------
@app.get("/secret-data/")
def secret_data(x_api_key: str = Header(None)):
    db = SessionLocal()
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API Key missing")

    record = db.query(APIKey).filter(APIKey.key == x_api_key).first()
    if not record:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    return {"message": f"Welcome {record.owner}, here is your secret data!"}

# ---------- List All Keys (Admin only) ----------
@app.get("/list-keys/")
def list_keys(admin_pass: str):
    if admin_pass != "admin123":
        raise HTTPException(status_code=403, detail="Unauthorized")
    db = SessionLocal()
    keys = db.query(APIKey).all()
    return [{"owner": k.owner, "api_key": k.key} for k in keys]
