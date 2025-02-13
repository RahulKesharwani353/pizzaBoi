from fastapi import Depends, FastAPI, Security
from fastapi.routing import APIRoute
from fastapi.security import HTTPBearer
from fastapi.openapi.utils import get_openapi
from auth_routes import auth_router
from order_routes import order_router
import inspect, re

app=FastAPI()

security = HTTPBearer(
    scheme_name="Bearer Auth",  # Match this name with security scheme
    description="JWT Bearer Token",
    auto_error=True
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Pizza Delivery API",
        description="""
        ## 🍕 Pizza Delivery API
        
        ### Authentication
        This API uses JWT Bearer token authentication.
        
        1. First, get your token from the `/auth/login` endpoint
        2. Then, use the token in the Authorize button above
        3. Enter your token without Bearer prefix
        """,
        version="1.0",
        routes=app.routes,
    )

    # Add global security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "Bearer Auth": {  # This name must match in both places
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    # Apply security to non-auth routes
    for path in openapi_schema["paths"]:
        if not path.startswith("/auth"):
            for method in openapi_schema["paths"][path]:
                openapi_schema["paths"][path][method]["security"] = [{"Bearer Auth": []}]  # Use same name here

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Include routers with explicit security
app.include_router(auth_router)
app.include_router(
    order_router,
    dependencies=[Security(security)]  # Use Security instead of Depends for better OpenAPI docs
)