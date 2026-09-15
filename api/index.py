import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app
from starlette.requests import Request
from starlette.responses import JSONResponse

@app.middleware("http")
async def log_path(request: Request, call_next):
    response = await call_next(request)
    if response.status_code == 404:
        return JSONResponse({
            "error": "not_found",
            "requested_path": request.url.path,
            "scope_path": request.scope.get("path"),
            "root_path": request.scope.get("root_path")
        }, status_code=404)
    return response
