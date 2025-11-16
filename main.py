import re
import uvicorn
import requests

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse

from app.routers import auth, entrypoints, secured
from app.schemas.user import UrlRequest

origins = [
    "http://localhost:8100/",
    "http://localhost:8100",
    "http://localhost",
    "http://127.0.0.1:8100",
]

limiter = Limiter(key_func=get_remote_address, default_limits=["1/minute"])
app = FastAPI()

# Add Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
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

#SECURE: Run application with TLS/SSL
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, ssl_certfile='./ssl_certs/example.com+5.pem', ssl_keyfile="./ssl_certs/./example.com+5-key.pem")

### NOT-SECURE ###
# 1. A02:2021 – Cryptographic Failures:Run application without TLS/SSL --> no confidentiality and integrity guarantess with the client
# if __name__ == "__main__":
#     uvicorn.run("main:app", host="0.0.0.0", port=8000,)

