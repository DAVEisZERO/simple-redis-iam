from fastapi import FastAPI
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, entrypoints, secured
import requests
from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse

origins = [
    "http://localhost:8100/",
    "http://localhost:8100",
    "http://localhost",
    "http://127.0.0.1:8100",
]

app = FastAPI()

# Arrange CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # TODO: restrict methods
    allow_headers=["*"], # TODO: restrict headers
)


app.include_router(auth.router, prefix="/api/v1/auth")
app.include_router(entrypoints.router, prefix="/api/v1/entrypoints")   
app.include_router(secured.router, prefix="/api/v1")


### INSECURE DEMO TO CHECK IF A LETTERBOXD URL IS VALID AND EXISTS ###
@app.get("/fetchletterbopxdurl")
def redirect_admin(request: Request):
    response = requests.get("https://letterboxd.com/davebeer/")
    #file://C:\Windows\System32\drivers\etc\hosts
    #file://C:\Windows\win.ini
    #GET http://127.0.0.1:6379 --> blind-SSRF to check the type of server
    return {"status": "deleted"}



# @app.get("/api/v1/")
# def read_root(token: Annotated[str, Depends(OAUTH2_SCHEME)]):
#      result = get_session_redis(token)

#      if result != None:
#         return {"Status": token + " is valid",
#                 "user": result }
#      else:                      
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

    
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, ssl_certfile='./ssl_certs/example.com+5.pem', ssl_keyfile="./ssl_certs/./example.com+5-key.pem")