# --- Imports ---
import os
import requests
import sqlite3
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

# --- Environment Setup ---
load_dotenv()

# --- App and Templates ---


app = FastAPI(title="Multi-Service OAuth API")
templates = Jinja2Templates(directory="templates")


# OAuth provider configurations (load from YAML)
def load_providers():
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "config/providers.yaml")
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    def expand(val):
        if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
            return os.getenv(val[2:-1], "")
        return val
    def expand_dict(d):
        return {k: expand(v) if not isinstance(v, dict) else expand_dict(v) for k, v in d.items()}
    return expand_dict(raw)

PROVIDERS = load_providers()


# --- UI route for Jira search ---



# --- Helper for Jira search logic ---
async def perform_jira_search(jql: str, user_id: str):
    try:
        # First get accessible resources (Jira instances)
        response = await api_client.make_request(
            user_id,
            "jira",
            "GET",
            "https://api.atlassian.com/oauth/token/accessible-resources",
        )
        response.raise_for_status()
        resources = response.json()
        if not resources:
            raise Exception("No accessible Jira instances found")
        cloud_id = resources[0]["id"]
        # Search issues
        search_response = await api_client.make_request(
            user_id,
            "jira",
            "GET",
            f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/search",
            params={"jql": jql, "maxResults": 20},
        )
        search_response.raise_for_status()
        data = search_response.json()
        return data, None
    except Exception as ex:
        return None, str(ex)


# --- Dependency to get current user ---
def get_current_user(request: Request) -> str:
    user_id = request.session.get("user_id")
    if not user_id:
        user_id = f"user_{uuid.uuid4().hex[:8]}"
        request.session["user_id"] = user_id
    return user_id




# Add session middleware
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY")
if (
    not SESSION_SECRET_KEY
    or SESSION_SECRET_KEY == "your-secret-key-change-in-production"
):
    raise RuntimeError(
        "SESSION_SECRET_KEY environment variable must be set and not use the default value for production security."
    )
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

# OAuth provider configurations
PROVIDERS = {
    "jira": {
        "client_id": os.getenv("JIRA_CLIENT_ID", ""),
        "client_secret": os.getenv("JIRA_CLIENT_SECRET", ""),
        "authorize_url": "https://auth.atlassian.com/authorize",
        "token_url": "https://auth.atlassian.com/oauth/token",
        "audience": "api.atlassian.com",
        "scope": "read:jira-work write:jira-work",
    },
    "github": {
        "client_id": os.getenv("GITHUB_CLIENT_ID", ""),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET", ""),
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scope": "repo user",
    },
    "google_drive": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "openid email profile https://www.googleapis.com/auth/drive.readonly",
    },
    "github_app": {
        "app_id": os.getenv("GITHUB_APP_ID"),
        "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY"),
        "installation_id": os.getenv("GITHUB_APP_INSTALLATION_ID"),
    },
    "github_app_oauth": {
        "client_id": os.getenv("GITHUB_APP_CLIENT_ID", ""),
        "client_secret": os.getenv("GITHUB_APP_CLIENT_SECRET", ""),
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scope": "user,repo,read:org,workflow,read:public_key,admin:repo_hook,read:repo_hook,write:repo_hook,admin:org,admin:public_key,admin:org_hook,read:discussion,write:discussion,admin:gpg_key,workflow,write:packages,read:packages,delete:packages,admin:enterprise,manage_billing,read:user,read:enterprise,read:project,write:project,delete:project,read:org,write:org,delete:org,admin:org,admin:org_hook,read:public_key,write:public_key,admin:public_key,read:gpg_key,write:gpg_key,admin:gpg_key,read:repo_hook,write:repo_hook,admin:repo_hook,read:discussion,write:discussion,admin:discussion,read:packages,write:packages,delete:packages,read:pages,write:pages,admin:pages,read:enterprise,write:enterprise,admin:enterprise,read:user,write:user,admin:user,read:project,write:project,admin:project,read:org,write:org,admin:org,read:public_key,write:public_key,admin:public_key,read:gpg_key,write:gpg_key,admin:gpg_key,read:repo_hook,write:repo_hook,admin:repo_hook,read:discussion,write:discussion,admin:discussion,read:packages,write:packages,delete:packages,read:pages,write:pages,admin:pages,read:enterprise,write:enterprise,admin:enterprise,read:user,write:user,admin:user,read:project,write:project,admin:project"
    },
    "lucidchart": {
        "client_id": os.getenv("LUCIDCHART_CLIENT_ID", ""),
        "client_secret": os.getenv("LUCIDCHART_CLIENT_SECRET", ""),
        "authorize_url": "https://lucid.app/oauth2/authorize",
        "token_url": "https://lucid.app/oauth2/token",
        "scope": "documents:read",
    },
}


# Function to generate GitHub App JWT
def generate_github_app_jwt(app_id: str, private_key: str) -> str:
    import jwt
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    payload = {"iat": now, "exp": now + timedelta(minutes=10), "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


# Function to get GitHub App installation access token
def get_github_app_access_token(
    app_id: str, private_key: str, installation_id: str
) -> str:
    jwt_token = generate_github_app_jwt(app_id, private_key)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
    }
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
@app.get("/api/jira/search", response_class=HTMLResponse, tags=["jira"])
async def jira_search_ui(request: Request, jql: str = "", user_id: str = Depends(get_current_user)):
    issues = None
    error = None
    if jql:
        data, error = await perform_jira_search(jql, user_id)
        if data:
            issues = data.get("issues", [])
    return templates.TemplateResponse(
        "search.html",
        {"request": request, "jql": jql, "issues": issues, "error": error},
    )

@app.get("/api/google_drive/search", response_class=HTMLResponse, tags=["google_drive"])
async def google_drive_search_ui(request: Request, q: str = "", user_id: str = Depends(get_current_user)):
    results = None
    error = None
    if q:
        try:
            response = await api_client.make_request(
                user_id,
                "google_drive",
                "GET",
                "https://www.googleapis.com/drive/v3/files",
                params={
                    "q": f"name contains '{q}'",
                    "fields": "files(id, name, mimeType, webViewLink)",
                    "pageSize": 20,
                },
            )
            response.raise_for_status()
            data = response.json()
            if hasattr(data, "__await__"):
                data = await data
            results = data.get("files", [])
        except Exception as ex:
            error = str(ex)
    return templates.TemplateResponse(
        "google_drive_search.html",
        {"request": request, "q": q, "results": results, "error": error},
    )




# Register Datadog with Authlib if present in PROVIDERS (from YAML)
if "datadog" in PROVIDERS and isinstance(PROVIDERS["datadog"], dict):
    datadog_cfg = PROVIDERS["datadog"]
    if datadog_cfg.get("client_id") and datadog_cfg.get("client_secret"):
        oauth.register(
            name="datadog",
            client_id=datadog_cfg["client_id"],
            client_secret=datadog_cfg["client_secret"],
            authorize_url=datadog_cfg["authorize_url"],
            access_token_url=datadog_cfg["token_url"],
            client_kwargs={"scope": datadog_cfg["scope"]},
        )

@app.get("/auth/datadog", tags=["auth"])
async def auth_datadog(request: Request, user_id: str = Depends(get_current_user)):
    datadog_cfg = PROVIDERS["datadog"] if isinstance(PROVIDERS.get("datadog"), dict) else {}
    if not (datadog_cfg.get("client_id") and datadog_cfg.get("client_secret")):
        raise HTTPException(status_code=500, detail="Datadog credentials not configured.")
    client = oauth.create_client("datadog")
    if client is None:
        raise HTTPException(status_code=500, detail="OAuth client for Datadog could not be created.")
    redirect_uri = str(request.url_for("callback", provider="datadog"))
    return await client.authorize_redirect(request, redirect_uri)

@app.get("/api/lucidchart/search", response_class=HTMLResponse, tags=["lucidchart"])
async def lucidchart_search_ui(request: Request, q: str = "", user_id: str = Depends(get_current_user)):
    results = None
    error = None
    if q:
        try:
            response = await api_client.make_request(
                user_id,
                "lucidchart",
                "GET",
                "https://api.lucidchart.com/v1/documents",
                params={"q": q, "page_size": 20},
            )
            response.raise_for_status()
            data = response.json()
            results = data.get("documents", [])
        except Exception as ex:
            error = str(ex)
    return templates.TemplateResponse(
        "lucidchart_search.html",
        {"request": request, "q": q, "results": results, "error": error},
    )

@app.get("/api/lucidchart/preview/{doc_id}", response_class=HTMLResponse, tags=["lucidchart"])
async def lucidchart_preview(doc_id: str, request: Request, user_id: str = Depends(get_current_user)):
    try:
        response = await api_client.make_request(
            user_id,
            "lucidchart",
            "GET",
            f"https://api.lucidchart.com/v1/documents/{doc_id}",
        )
        response.raise_for_status()
        doc = response.json()
        view_url = doc.get("viewURL") or f"https://lucid.app/documents/view/{doc_id}"
        return HTMLResponse(
            f'<h2>{doc.get("name", "Lucidchart Document")}</h2>'
            f'<a href="{view_url}" target="_blank">Open in Lucidchart</a>'
        )
    except Exception as ex:
        return HTMLResponse(f"<b>Error:</b> {str(ex)}", status_code=400)


class TokenManager:
    def __init__(self, db_path: str = "tokens.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                user_id TEXT,
                provider TEXT,
                access_token TEXT,
                refresh_token TEXT,
                expires_at TIMESTAMP,
                token_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, provider)
            )
        """)
        conn.commit()
        conn.close()

    def save_token(self, user_id: str, provider: str, token_data: Dict[str, Any]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        expires_at = None
        if "expires_in" in token_data:
            expires_at = datetime.now() + timedelta(seconds=token_data["expires_in"])

        cursor.execute(
            """
            INSERT OR REPLACE INTO user_tokens 
            (user_id, provider, access_token, refresh_token, expires_at, token_data)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                user_id,
                provider,
                token_data.get("access_token"),
                token_data.get("refresh_token"),
                expires_at,
                json.dumps(token_data),
            ),
        )
        conn.commit()
        conn.close()

    def get_token(self, user_id: str, provider: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT access_token, refresh_token, expires_at, token_data 
            FROM user_tokens 
            WHERE user_id = ? AND provider = ?
        """,
            (user_id, provider),
        )

        result = cursor.fetchone()
        conn.close()

        if not result:
            return None

        access_token, refresh_token, expires_at, token_data = result
        token_data = json.loads(token_data)

        # Check if token is expired
        if expires_at:
            expires_at = datetime.fromisoformat(expires_at)
            if datetime.now() > expires_at:
                # Try to refresh token
                refreshed_token = self.refresh_token(user_id, provider, refresh_token)
                if refreshed_token:
                    return refreshed_token
                return None

        return token_data

    def refresh_token(
        self, user_id: str, provider: str, refresh_token: str
    ) -> Optional[Dict[str, Any]]:
        if not refresh_token:
            return None

        provider_config = PROVIDERS[provider]

        try:
            client = OAuth2Session(
                provider_config["client_id"], refresh_token=refresh_token
            )

            token = client.refresh_token(
                provider_config["token_url"],
                client_secret=provider_config["client_secret"],
            )

            # Save refreshed token
            self.save_token(user_id, provider, token)
            return token

        except Exception as e:
            print(f"Failed to refresh token for {provider}: {e}")
            return None

    def is_connected(self, user_id: str, provider: str) -> bool:
        token = self.get_token(user_id, provider)
        return token is not None

    def get_all_connections(self, user_id: str) -> Dict[str, bool]:
        connections = {}
        for provider in PROVIDERS.keys():
            connections[provider] = self.is_connected(user_id, provider)
        return connections


token_manager = TokenManager()


# Update APIClient to support GitHub App authentication
class APIClient:
    def __init__(self, token_manager: TokenManager):
        self.token_manager = token_manager

    async def make_request(
        self, user_id: str, provider: str, method: str, url: str, **kwargs
    ) -> "httpx.Response":
        import httpx
        async with httpx.AsyncClient() as client:
            if provider == "github_app":
                app_config = PROVIDERS["github_app"]
                if (
                    not app_config["app_id"]
                    or not app_config["private_key"]
                    or not app_config["installation_id"]
                ):
                    raise HTTPException(
                        status_code=500,
                        detail="GitHub App credentials not configured. Please set GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and GITHUB_APP_INSTALLATION_ID environment variables.",
                    )
                access_token = get_github_app_access_token(
                    app_config["app_id"],
                    app_config["private_key"],
                    app_config["installation_id"],
                )
                headers = kwargs.get("headers", {})
                headers["Authorization"] = f"Bearer {access_token}"
                kwargs["headers"] = headers
                response = await client.request(method, url, **kwargs)
                return response
            else:
                token_data = self.token_manager.get_token(user_id, provider)
                if not token_data:
                    raise HTTPException(
                        status_code=401,
                        detail=f"No valid token for {provider}. Please connect your account first.",
                    )
                headers = kwargs.get("headers", {})
                headers["Authorization"] = f"Bearer {token_data['access_token']}"
                kwargs["headers"] = headers

                response = await client.request(method, url, **kwargs)

                if response.status_code == 401 and provider != "github_app":
                    # Token might be expired, try to refresh
                    refresh_token_val = token_data.get("refresh_token")
                    if refresh_token_val is not None:
                        refreshed_token = self.token_manager.refresh_token(
                            user_id, provider, refresh_token_val
                        )
                    else:
                        refreshed_token = None
                    if refreshed_token:
                        headers["Authorization"] = f"Bearer {refreshed_token['access_token']}"
                        response = await client.request(method, url, **kwargs)

                return response


api_client = APIClient(token_manager)


# Routes

@app.get("/", response_class=HTMLResponse, tags=["ui"])
async def index(request: Request, user_id: str = Depends(get_current_user)):
    # Ensure connections includes all providers from PROVIDERS
    connections = {provider: token_manager.is_connected(user_id, provider) for provider in PROVIDERS.keys()}
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user_id": user_id, "connections": connections},
    )


@app.get("/auth/{provider}", tags=["auth"])
async def auth(
    provider: str, request: Request, user_id: str = Depends(get_current_user)
):
    if provider not in PROVIDERS:
        raise HTTPException(
            status_code=400, detail=f"Provider {provider} not supported"
        )

    config = PROVIDERS[provider]
    # Only check for client_id/client_secret if they exist in config
    if "client_id" in config and "client_secret" in config:
        if not config["client_id"] or not config["client_secret"]:
            raise HTTPException(
                status_code=500,
                detail=f"{provider.title()} credentials not configured. Please set {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET environment variables.",
            )
        client = oauth.create_client(provider)
        if client is None:
            raise HTTPException(
                status_code=500, detail=f"OAuth client for {provider} could not be created."
            )
        redirect_uri = str(request.url_for("callback", provider=provider))
        if provider == "jira":
            return await client.authorize_redirect(
                request, redirect_uri, audience=PROVIDERS["jira"]["audience"]
            )
        else:
            return await client.authorize_redirect(request, redirect_uri)
    else:
        # For non-OAuth providers like github_app
        raise HTTPException(
            status_code=400,
            detail=f"Provider {provider} does not support interactive OAuth login."
        )


@app.get("/callback/{provider}", tags=["auth"])
async def callback(
    provider: str, request: Request, user_id: str = Depends(get_current_user)
):
    if provider not in PROVIDERS:
        raise HTTPException(
            status_code=400, detail=f"Provider {provider} not supported"
        )

    client = oauth.create_client(provider)
    if client is None:
        raise HTTPException(
            status_code=500, detail=f"OAuth client for {provider} could not be created."
        )
    token = await client.authorize_access_token(request)
    print(f"[DEBUG] Received token for {provider}: {json.dumps(token, indent=2)}")
    # Save token
    token_manager.save_token(user_id, provider, token)
    return RedirectResponse(url="/")


@app.get("/api/github/issues", tags=["github"])
async def github_issues(user_id: str = Depends(get_current_user)):
    """List issues assigned to the authenticated GitHub user"""
    try:
        response = await api_client.make_request(
            user_id,
            "github",
            "GET",
            "https://api.github.com/issues",
            params={"filter": "assigned", "per_page": 10},
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GitHub API error: {str(e)}")


@app.get("/api/jira/search", tags=["jira"])
async def jira_search(
    jql: str = "project IS NOT EMPTY", user_id: str = Depends(get_current_user)
):
    """Search Jira issues"""
    data, error = await perform_jira_search(jql, user_id)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return data


@app.get("/api/github/user", tags=["github"])
async def github_user(user_id: str = Depends(get_current_user)):
    """Get GitHub user profile"""
    try:
        response = await api_client.make_request(
            user_id, "github", "GET", "https://api.github.com/user"
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GitHub API error: {str(e)}")


@app.get("/api/github/repos", tags=["github"])
async def github_repos(user_id: str = Depends(get_current_user)):
    """Get user's GitHub repositories"""
    try:
        response = await api_client.make_request(
            user_id,
            "github",
            "GET",
            "https://api.github.com/user/repos",
            params={"per_page": 10, "sort": "updated"},
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GitHub API error: {str(e)}")


@app.get("/api/google_drive/userinfo", tags=["google_drive"])
async def google_drive_userinfo(user_id: str = Depends(get_current_user)):
    """Get Google Drive user info"""
    try:
        response = await api_client.make_request(
            user_id, "google_drive", "GET", "https://www.googleapis.com/oauth2/v2/userinfo"
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google Drive API error: {str(e)}")


@app.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "providers": list(PROVIDERS.keys())}


# Print the current working directory for debugging
print("Current working directory:", os.getcwd())

# app.mount("/static", StaticFiles(directory=os.path.join(os.getcwd(), "static")), name="static")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="localhost", port=8000)
