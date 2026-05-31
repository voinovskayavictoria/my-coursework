from fastapi import FastAPI, Response
from fastapi.staticfiles import StaticFiles

from webapp.auth import auth_context_middleware, router as auth_router
from webapp.pages import router as pages_router
from webapp.scans.routes import router as scans_router
from webapp.session import session_cookie_middleware
def create_app() -> FastAPI:
    app = FastAPI(title="Web Vulnerability Scanner")
    app.mount("/static", StaticFiles(directory="."), name="static")

    app.middleware("http")(session_cookie_middleware)
    app.middleware("http")(auth_context_middleware)

    @app.get("/.well-known/appspecific/com.chrome.devtools.json")
    async def chrome_devtools_stub():
        return Response(status_code=204)

    app.include_router(pages_router)
    app.include_router(auth_router)
    app.include_router(scans_router)
    return app
