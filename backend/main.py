# This is backend file
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import sqlite3

# FastAPI app
app = FastAPI()


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow your React app's origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)





# Database setup
conn = sqlite3.connect("marketplace.db", check_same_thread=False)
cursor = conn.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
)
""")
conn.commit()

#2 add new table products
# Create products table
cursor.execute("""
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price FLOAT NOT NULL,
    category TEXT,
    seller_id INTEGER NOT NULL,
    FOREIGN KEY (seller_id) REFERENCES users (id)
)
""")
conn.commit()

class Product(BaseModel):
    name: str
    description: str | None = None
    price: float
    category: str | None = None
    seller_id: int




# JWT settings
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(BaseModel):
    username: str

class UserInDB(User):
    password_hash: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user:
        return UserInDB(username=user[1], password_hash=user[2])

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.password_hash):
        return False
    return user

# Routes
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/signup")
async def signup(username: str, password: str):
    user = get_user(username)
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    password_hash = get_password_hash(password)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    return {"message": "User created successfully"}

@app.get("/profile", response_model=User)
async def read_profile(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Endpoint to list a new product
@app.post("/products")
async def create_product(product: Product, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Insert product into the database
    cursor.execute(
        "INSERT INTO products (name, description, price, category, seller_id) VALUES (?, ?, ?, ?, ?)",
        (product.name, product.description, product.price, product.category, product.seller_id))
    conn.commit()
    return {"message": "Product listed successfully"}

# Endpoint to fetch all products
@app.get("/products")
async def get_products():
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    return {"products": products}