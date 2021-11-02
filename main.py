from fastapi import Depends, FastAPI, Header, HTTPException, status
from jose import jwt
from datetime import datetime, timedelta
import time
from pydantic import BaseModel, constr
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#crypt utils
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


#jwt token parameters
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#user database
fake_user_db ={
    "mustafa" : {
        "username":"mustafa",
        "password":"$2b$12$.JVXGhi5h0sV26MTKrpXAe7UDUnIABKyTZ0.dAZrLANWO52BTyKDG"
    }
}

# pydantic model for validating token api calls
class UserAuthModel(BaseModel):
    username:constr(max_length=10, min_length=5)
    password:str
#m
class Token(BaseModel):
    access_token: str
    token_type: str
    
app = FastAPI()

#utility fonction for generating jwt token
def get_jwt_token(username:str):
    expire = datetime.utcnow() + timedelta(minutes=150)
    expire = int(time.mktime(expire.timetuple()))
    data={
        "sub": f"user:{username}",
        "secret" :"ksjdh343k4j3hk4jh3kj4",
        "expire":expire            
    }      
    _now =int(time.mktime(datetime.now().timetuple()))
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM) 

#dependency 1     
def get_athentication_header(Authorization=Header(...)):
    return Authorization[7:]

#dependency 2  -> dependency 1
def get_current_user(token: str = Depends(get_athentication_header)):
    if token is None:
        raise HTTPException(
            status_code=401,
            detail="no auhentication code provided"
        )
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("user")
    return username

#depends on get_current_user
@app.get("/items/")
async def read_items(user: str =Depends(get_current_user)):
    return {"ITEMS OF ": user}

#depends on get_current_user
@app.post("/auth/")
async def read_items(user: str =Depends(get_current_user)):
    return f"welcome {user}"

#no dependency only pydantic validation
@app.post("/token/", response_model=Token)
async def read_items(user: UserAuthModel):
    #check if user in user database   
    if user.username in fake_user_db:
        hashed_password = fake_user_db[user.username]['password']
        
        #check if username/pasword matches
        if user.username == "mustafa" and verify_password(user.password, hashed_password):
            encoded_jwt = get_jwt_token(user.username)
            return {
                "access_token": encoded_jwt, 
                "token_type": "bearer"
            }
    #user not found or username/password doesn't match
    raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="no user found with this username and password "
            )        
         

import uvicorn
if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)

