
# --- Imports ---
import os
import requests
import sqlite3
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

# --- Environment Setup ---
load_dotenv()

# --- App and Templates ---
app = FastAPI(title="Multi-Service OAuth API")
templates = Jinja2Templates(directory="templates")



# --- UI route for Jira search ---

# --- Helper for Jira search logic ---
async def perform_jira_search(jql: str, user_id: str):
    try:
        # First get accessible resources (Jira instances)
        response = api_client.make_request(
            user_id, 'jira', 'GET',
            'https://api.atlassian.com/oauth/token/accessible-resources'
        )
        response.raise_for_status()
        resources = response.json()
        if not resources:
            raise Exception("No accessible Jira instances found")
        cloud_id = resources[0]['id']
        # Search issues
        search_response = api_client.make_request(
            user_id, 'jira', 'GET',
            f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/search',
            params={'jql': jql, 'maxResults': 10}
        )
        search_response.raise_for_status()
        return search_response.json(), None
    except requests.RequestException as e:
        return None, f"Jira API error: {str(e)}"
    except Exception as ex:
        return None, str(ex)


@app.get("/search", response_class=HTMLResponse)
async def search_ui(request: Request, jql: str = None):
    """UI to trigger and show Jira search results"""
    issues = None
    error = None
    if jql:
        user_id = get_current_user(request)
        data, error = await perform_jira_search(jql, user_id)
        if data:
            issues = data.get("issues", [])
    return templates.TemplateResponse("search.html", {"request": request, "jql": jql, "issues": issues, "error": error})




# --- Dependency to get current user ---
def get_current_user(request: Request) -> str:
    # In a real app, you'd get this from JWT token or session
    user_id = request.session.get('user_id')
    if not user_id:
        # Create a demo user for this session
        user_id = f"user_{uuid.uuid4().hex[:8]}"
        request.session['user_id'] = user_id
    return user_id

# --- Google Drive Search UI ---
@app.get("/google_drive_search", response_class=HTMLResponse)
async def google_drive_search_ui(request: Request, q: str = None, user_id: str = Depends(get_current_user)):
    results = None
    error = None
    if q:
        try:
            response = api_client.make_request(
                user_id, 'google', 'GET',
                'https://www.googleapis.com/drive/v3/files',
                params={
                    'q': f"name contains '{q}'",
                    'fields': 'files(id, name, mimeType, webViewLink)',
                    'pageSize': 20
                }
            )
            try:
                response.raise_for_status()
            except requests.HTTPError as http_err:
                print(f"[DEBUG] Google Drive API error: {response.status_code} {response.text}")
                # Show error details in UI
                try:
                    error_json = response.json()
                    error = f"{response.status_code} {error_json.get('error', {}).get('message', response.text)}"
                except Exception:
                    error = f"{response.status_code} {response.text}"
                return templates.TemplateResponse("google_drive_search.html", {"request": request, "q": q, "results": None, "error": error})
            data = response.json()
            results = data.get('files', [])
        except Exception as ex:
            error = str(ex)
    return templates.TemplateResponse("google_drive_search.html", {"request": request, "q": q, "results": results, "error": error})

# Add session middleware
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY")
if not SESSION_SECRET_KEY or SESSION_SECRET_KEY == "your-secret-key-change-in-production":
    raise RuntimeError("SESSION_SECRET_KEY environment variable must be set and not use the default value for production security.")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

# OAuth provider configurations
PROVIDERS = {
    'jira': {
        'client_id': os.getenv('JIRA_CLIENT_ID'),
        'client_secret': os.getenv('JIRA_CLIENT_SECRET'),
        'authorize_url': 'https://auth.atlassian.com/authorize',
        'token_url': 'https://auth.atlassian.com/oauth/token',
        'audience': 'api.atlassian.com',
        'scope': 'read:jira-work write:jira-work'
    },
    'github': {
        'client_id': os.getenv('GITHUB_CLIENT_ID'),
        'client_secret': os.getenv('GITHUB_CLIENT_SECRET'),
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'scope': 'repo user'
    },
    'google': {
        'client_id': os.getenv('GOOGLE_CLIENT_ID'),
        'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
        'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'scope': 'openid email profile https://www.googleapis.com/auth/drive.readonly'
    }
}

# Validate required environment variables
missing_vars = []
for provider, config in PROVIDERS.items():
    if not config['client_id']:
        missing_vars.append(f"{provider.upper()}_CLIENT_ID")
    if not config['client_secret']:
        missing_vars.append(f"{provider.upper()}_CLIENT_SECRET")
    print(f"{provider.title()} credentials loaded: {'Yes' if config['client_id'] and config['client_secret'] else 'No'}")

if missing_vars:
    print("Warning: Missing environment variables:", ", ".join(missing_vars))
    print("Please set these in your .env file or environment")

# Initialize OAuth
oauth = OAuth()

# Register providers (only if credentials are available)
for provider_name, config in PROVIDERS.items():
    if config['client_id'] and config['client_secret']:
        if provider_name == 'google':
            oauth.register(
                name=provider_name,
                client_id=config['client_id'],
                client_secret=config['client_secret'],
                server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                client_kwargs={'scope': config['scope']}
            )
        else:
            oauth.register(
                name=provider_name,
                client_id=config['client_id'],
                client_secret=config['client_secret'],
                authorize_url=config['authorize_url'],
                access_token_url=config['token_url'],
                client_kwargs={'scope': config['scope']} if 'scope' in config else {}
            )
    else:
        print(f"Skipping {provider_name} registration - missing credentials")

class TokenManager:
    def __init__(self, db_path: str = 'tokens.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
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
        ''')
        conn.commit()
        conn.close()
    
    def save_token(self, user_id: str, provider: str, token_data: Dict[str, Any]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = None
        if 'expires_in' in token_data:
            expires_at = datetime.now() + timedelta(seconds=token_data['expires_in'])
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_tokens 
            (user_id, provider, access_token, refresh_token, expires_at, token_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            provider,
            token_data.get('access_token'),
            token_data.get('refresh_token'),
            expires_at,
            json.dumps(token_data)
        ))
        conn.commit()
        conn.close()
    
    def get_token(self, user_id: str, provider: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT access_token, refresh_token, expires_at, token_data 
            FROM user_tokens 
            WHERE user_id = ? AND provider = ?
        ''', (user_id, provider))
        
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
    
    def refresh_token(self, user_id: str, provider: str, refresh_token: str) -> Optional[Dict[str, Any]]:
        if not refresh_token:
            return None
        
        provider_config = PROVIDERS[provider]
        
        try:
            client = OAuth2Session(
                provider_config['client_id'],
                refresh_token=refresh_token
            )
            
            token = client.refresh_token(
                provider_config['token_url'],
                client_secret=provider_config['client_secret']
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

class APIClient:
    def __init__(self, token_manager: TokenManager):
        self.token_manager = token_manager
    
    def make_request(self, user_id: str, provider: str, method: str, url: str, **kwargs) -> requests.Response:
        token_data = self.token_manager.get_token(user_id, provider)
        if not token_data:
            raise HTTPException(
                status_code=401, 
                detail=f"No valid token for {provider}. Please connect your account first."
            )
        
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {token_data['access_token']}"
        kwargs['headers'] = headers
        
        response = requests.request(method, url, **kwargs)
        
        if response.status_code == 401:
            # Token might be expired, try to refresh
            refreshed_token = self.token_manager.refresh_token(
                user_id, provider, token_data.get('refresh_token')
            )
            if refreshed_token:
                headers['Authorization'] = f"Bearer {refreshed_token['access_token']}"
                response = requests.request(method, url, **kwargs)
        
        return response

api_client = APIClient(token_manager)



# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user_id: str = Depends(get_current_user)):
    connections = token_manager.get_all_connections(user_id)
    
    html_content = f"""
    <html>
        <head>
            <title>OAuth Integrations</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .connected {{ color: green; }}
                .disconnected {{ color: red; }}
                ul {{ list-style-type: none; padding: 0; }}
                li {{ margin: 10px 0; }}
                a {{ text-decoration: none; background: #007bff; color: white; padding: 5px 10px; border-radius: 3px; }}
                a:hover {{ background: #0056b3; }}
                .search-box {{ margin: 2em 0; }}
            </style>
        </head>
        <body>
            <h1>OAuth Integrations</h1>
            <p>User: {user_id}</p>
            <h2>Connections:</h2>
            <ul>
                {''.join([f'''<li>
                    <strong>{provider.title()}:</strong> 
                    <span class="{'connected' if connected else 'disconnected'}">
                        {'✓ Connected' if connected else '✗ Not connected'}
                    </span>
                    <a href="/auth/{provider}">Connect</a>
                </li>''' for provider, connected in connections.items()])}
            </ul>
            <div class="search-box">
                <form method="get" action="/search" style="margin-bottom:1em;">
                    <label for="jql">Jira Search (JQL):</label>
                    <input type="text" id="jql" name="jql" value="project IS NOT EMPTY" size="40" required>
                    <button type="submit">Search</button>
                    <a href="/search" style="background:#6c757d;">Advanced…</a>
                </form>
                <form method="get" action="/google_drive_search">
                    <label for="q">Google Drive Search:</label>
                    <input type="text" id="q" name="q" value="" size="40" required>
                    <button type="submit">Search</button>
                </form>
            </div>
            <h2>Test API Calls:</h2>
            <ul>
                <li><a href="/api/jira/myself">Jira: Get current user</a></li>
                <li><a href="/api/github/user">GitHub: Get user profile</a></li>
                <li><a href="/api/google/userinfo">Google: Get user info</a></li>
            </ul>
        </body>
    </html>
    """
    return html_content

@app.get("/auth/{provider}")
async def auth(provider: str, request: Request, user_id: str = Depends(get_current_user)):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider {provider} not supported")
    
    # Check if provider has valid credentials
    if not PROVIDERS[provider]['client_id'] or not PROVIDERS[provider]['client_secret']:
        raise HTTPException(
            status_code=500, 
            detail=f"{provider.title()} credentials not configured. Please set {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET environment variables."
        )
    
    client = oauth.create_client(provider)
    
    # Build the correct redirect URI
    redirect_uri = str(request.url_for('callback', provider=provider))
    
    # For Jira, we need to include audience
    if provider == 'jira':
        return await client.authorize_redirect(
            request, 
            redirect_uri, 
            audience=PROVIDERS['jira']['audience']
        )
    else:
        return await client.authorize_redirect(request, redirect_uri)

@app.get("/callback/{provider}")
async def callback(provider: str, request: Request, user_id: str = Depends(get_current_user)):
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Provider {provider} not supported")
    
    client = oauth.create_client(provider)
    token = await client.authorize_access_token(request)
    print(f"[DEBUG] Received token for {provider}: {json.dumps(token, indent=2)}")
    
    # Save token
    token_manager.save_token(user_id, provider, token)
    
    return RedirectResponse(url="/")

@app.get("/api/github/issues")
async def github_issues(user_id: str = Depends(get_current_user)):
    """List issues assigned to the authenticated GitHub user"""
    try:
        response = api_client.make_request(
            user_id, 'github', 'GET',
            'https://api.github.com/issues',
            params={'filter': 'assigned', 'per_page': 10}
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"GitHub API error: {str(e)}")


@app.get("/api/jira/search")
async def jira_search(jql: str = "project IS NOT EMPTY", user_id: str = Depends(get_current_user)):
    """Search Jira issues"""
    data, error = await perform_jira_search(jql, user_id)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return data

@app.get("/api/github/user")
async def github_user(user_id: str = Depends(get_current_user)):
    """Get GitHub user profile"""
    try:
        response = api_client.make_request(
            user_id, 'github', 'GET', 
            'https://api.github.com/user'
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"GitHub API error: {str(e)}")

@app.get("/api/github/repos")
async def github_repos(user_id: str = Depends(get_current_user)):
    """Get user's GitHub repositories"""
    try:
        response = api_client.make_request(
            user_id, 'github', 'GET', 
            'https://api.github.com/user/repos',
            params={'per_page': 10, 'sort': 'updated'}
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"GitHub API error: {str(e)}")

@app.get("/api/google/userinfo")
async def google_userinfo(user_id: str = Depends(get_current_user)):
    """Get Google user info"""
    try:
        response = api_client.make_request(
            user_id, 'google', 'GET', 
            'https://www.googleapis.com/oauth2/v2/userinfo'
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Google API error: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "providers": list(PROVIDERS.keys())}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)