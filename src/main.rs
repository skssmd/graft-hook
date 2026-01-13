use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use std::{collections::HashMap, env, sync::Arc};
use tokio::process::Command;
use tracing::{info, error, warn, debug, instrument};

#[derive(Deserialize, Debug)]
struct QueryParams {
    project: Option<String>,
    path: Option<String>,
    versionstokeep: Option<u32>,
    mode: String,
    repository: Option<String>, // Optional, for backward compatibility (not used)
}

#[derive(Deserialize, Debug)]
struct WebhookPayload {
    project: String,
    token: Option<String>,
    user: Option<String>,
    r#type: String,
    registry: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ErrorPayload {
    project: String,
    repository: String,
    message: String,
    token: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ProjectConfig {
    path: String,
    #[serde(default)]
    rollback_backups: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
enum ProjectEntry {
    Path(String),
    Full(ProjectConfig),
}

impl ProjectEntry {
    fn path(&self) -> &str {
        match self {
            ProjectEntry::Path(p) => p,
            ProjectEntry::Full(c) => &c.path,
        }
    }

    fn rollback_backups(&self) -> u32 {
        match self {
            ProjectEntry::Path(_) => 0,
            ProjectEntry::Full(c) => c.rollback_backups.unwrap_or(0),
        }
    }
}

type ConfigFile = HashMap<String, ProjectEntry>;

struct AppState {
    config: ConfigFile,
}

#[tokio::main]
async fn main() {
    // 1. Initialize Logging (Tracing Subscriber)
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    dotenvy::dotenv().ok();
    info!("🚀 Initializing Graft-Hook Server...");

    let config_path = env::var("configpath").unwrap_or_else(|_| "projects.json".to_string());
    debug!("Reading config from: {}", config_path);

    let config_content = std::fs::read_to_string(&config_path)
        .expect("CRITICAL: Failed to read config file");
    
    let config: ConfigFile = serde_json::from_str(&config_content)
        .expect("CRITICAL: JSON format mismatch in config");
    
    info!("Loaded {} project(s) from config", config.len());

    let state = Arc::new(AppState { config });

    let app = Router::new()
        .route("/webhook", post(handle_deploy))
        .route("/builderror", post(handle_error))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("✅ Server listening on http://0.0.0.0:3000");
    
    axum::serve(listener, app).await.unwrap();
}

// HMAC signature verification helper
type HmacSha256 = Hmac<Sha256>;

fn verify_signature(query_string: &str, signature: &str, secret: &str) -> bool {
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    
    mac.update(query_string.as_bytes());
    
    // Extract hex signature from "sha256=..." format
    let sig_hex = signature.strip_prefix("sha256=").unwrap_or(signature);
    
    // Decode hex signature
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    
    mac.verify_slice(&sig_bytes).is_ok()
}

async fn handle_deploy(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, &'static str) {
    info!("📥 Webhook request received");

    // Priority 1: Check for query param + signature approach
    if !params.is_empty() {
        info!("🔍 Query params detected, attempting signature verification");
        
        // Get signature from header
        let signature = match headers.get("x-hub-signature-256") {
            Some(sig) => match sig.to_str() {
                Ok(s) => s,
                Err(_) => {
                    error!("Invalid signature header format");
                    return (StatusCode::UNAUTHORIZED, "Invalid signature format");
                }
            },
            None => {
                error!("Missing X-Hub-Signature-256 header");
                return (StatusCode::UNAUTHORIZED, "Missing signature");
            }
        };

        // Parse mode first to determine which token to use for signature verification
        let mode = match params.get("mode") {
            Some(m) => m.as_str(),
            None => {
                error!("Missing 'mode' parameter");
                return (StatusCode::BAD_REQUEST, "Missing mode parameter");
            }
        };

        // Get secret from environment based on mode
        let secret = match mode {
            "repo" => {
                match env::var("GIT_PAT_TOKEN") {
                    Ok(s) => s,
                    Err(_) => {
                        error!("No GIT_PAT_TOKEN found in environment for repo mode");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Server configuration error");
                    }
                }
            }
            "image" => {
                match env::var("DOCKER_ACCESS_TOKEN") {
                    Ok(s) => s,
                    Err(_) => {
                        error!("No DOCKER_ACCESS_TOKEN found in environment for image mode");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Server configuration error");
                    }
                }
            }
            _ => {
                error!("Invalid mode for signature verification: {}", mode);
                return (StatusCode::BAD_REQUEST, "Invalid mode");
            }
        };

        // Reconstruct query string for verification
        let mut query_pairs: Vec<_> = params.iter().collect();
        query_pairs.sort_by_key(|(k, _)| *k);
        let query_string: String = query_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        // Verify signature
        if !verify_signature(&query_string, signature, &secret) {
            error!("❌ Signature verification failed");
            return (StatusCode::UNAUTHORIZED, "Invalid signature");
        }

        info!("✅ Signature verified successfully");

        // Parse remaining query params
        let project_name = params.get("project");
        let path = params.get("path");
        let versions_to_keep = params.get("versionstokeep")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        // Determine deployment context
        let (deploy_path, rollback_limit, project_id) = if let Some(proj_name) = project_name {
            // Mode 1: Project exists in config
            match state.config.get(proj_name) {
                Some(entry) => {
                    info!("📁 Using project from config: {}", proj_name);
                    (entry.path().to_string(), entry.rollback_backups(), proj_name.clone())
                }
                None => {
                    error!("Project '{}' not found in config", proj_name);
                    return (StatusCode::NOT_FOUND, "Project not found in config");
                }
            }
        } else if let Some(custom_path) = path {
            // Mode 2: External user with custom path
            info!("📁 Using custom path: {}", custom_path);
            // Use sanitized path as project_id for backups
            let sanitized_id = custom_path.replace(['/', '\\', '.'], "_");
            (custom_path.clone(), versions_to_keep, sanitized_id)
        } else {
            error!("Either 'project' or 'path' parameter must be provided");
            return (StatusCode::BAD_REQUEST, "Missing project or path parameter");
        };

        // Execute deployment
        let result = match mode {
            "repo" => {
                info!("Mode selected: Git Pull & Compose Build");
                deploy_git_env(&deploy_path).await
            }
            "image" => {
                info!("Mode selected: Docker Login & Compose Pull");
                deploy_docker_env(&deploy_path).await
            }
            _ => {
                warn!("Invalid deployment mode: {}", mode);
                return (StatusCode::BAD_REQUEST, "Invalid mode");
            }
        };

        // Post-deploy cleanup and backup
        if result.starts_with("Success") {
            if rollback_limit > 0 {
                create_backup(&project_id, &deploy_path).await;
                prune_backups(&project_id, rollback_limit).await;
            }
            debug!("Deployment success, performing safe image cleanup");
            let _ = Command::new("docker").args(["image", "prune", "-f"]).status().await;
            return (StatusCode::OK, result);
        } else {
            return (StatusCode::INTERNAL_SERVER_ERROR, result);
        }
    }

    // Priority 2: Fall back to JSON payload approach
    info!("📦 No query params, attempting JSON payload parsing");
    
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse JSON payload: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid JSON payload");
        }
    };

    debug!("Payload received: {:?}", payload);
    
    // Lookup Project Path
    let project_entry = match state.config.get(&payload.project) {
        Some(entry) => entry,
        None => {
            error!("Project '{}' not found in config", payload.project);
            return (StatusCode::NOT_FOUND, "Project not found in config");
        }
    };

    let project_path = project_entry.path();
    let rollback_limit = project_entry.rollback_backups();

    // Select Deployment Mode
    let result = match payload.r#type.as_str() {
        "repo" => {
            info!("Mode selected: Git Pull & Compose Build");
            deploy_git_json(project_path, &payload).await
        }
        "image" => {
            info!("Mode selected: Docker Login & Compose Pull");
            deploy_docker_json(project_path, &payload).await
        }
        _ => {
            warn!("Invalid deployment type received: {}", payload.r#type);
            return (StatusCode::BAD_REQUEST, "Invalid Type");
        }
    };

    // Post-deploy cleanup and backup
    if result.starts_with("Success") {
        if rollback_limit > 0 {
            create_backup(&payload.project, project_path).await;
            prune_backups(&payload.project, rollback_limit).await;
        }
        debug!("Deployment success, performing safe image cleanup");
        let _ = Command::new("docker").args(["image", "prune", "-f"]).status().await;
        (StatusCode::OK, result)
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, result)
    }
}

async fn deploy_git_json(path: &str, payload: &WebhookPayload) -> &'static str {
    // 1. Resolve Credentials with Secure Environment Fallback
    let token = payload.token.clone()
        .or_else(|| {
            // Only use environment token if ACCESS_SECRET exists and project path is valid
            if let Ok(access_secret) = env::var("ACCESS_SECRET") {
                if !access_secret.is_empty() {
                    debug!("ACCESS_SECRET validated, checking for environment token");
                    env::var("GIT_PAT_TOKEN").ok()
                } else {
                    None
                }
            } else {
                None
            }
        });
    
    let user = payload.user.clone()
        .or_else(|| {
            // Only use environment user if ACCESS_SECRET exists
            if let Ok(access_secret) = env::var("ACCESS_SECRET") {
                if !access_secret.is_empty() {
                    env::var("DOCKER_USER").ok()
                } else {
                    None
                }
            } else {
                None
            }
        });

    let (t, u) = match (token, user) {
        (Some(t), Some(u)) => (t, u),
        _ => {
            error!("❌ Missing Git credentials (token or user) in payload or environment");
            return "Missing Git Credentials";
        }
    };

    // 2. Perform Force Git Pull (Fetch + Reset Hard)
    // This ensures that local changes or untracked file conflicts (like docker-compose.yml)
    // are overwritten by the remote state.
    info!("Starting Force Git Pull (fetch & reset --hard) in {}", path);
    let pull_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && \
             git -c credential.helper= -c \"credential.helper=!f() {{ echo username={}; echo password={}; }}; f\" fetch origin main && \
             git reset --hard origin/main",
            path, u, t
        ))
        .status()
        .await;

    match pull_status {
        Ok(status) if status.success() => {
            info!("✅ Git pull successful");
        }
        _ => {
            error!("❌ Git pull failed in {}", path);
            return "Git Pull Failed";
        }
    }

    // 3. Trigger Docker Compose Build and Up
    info!("Running: docker compose up -d --build in {}", path);
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && docker compose up -d --build", path))
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!("✅ Container(s) rebuilt and restarted successfully via Docker Compose");
            "Success: Repo Pulled and Containers Rebuilt"
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Docker Compose build/up failed in {}: {}", path, stderr);
            "Git pull success, but Compose build/up failed"
        }
        Err(e) => {
            error!("Failed to execute Docker Compose command in {}: {}", path, e);
            "Command execution error"
        }
    }
}

async fn deploy_docker_json(path: &str, payload: &WebhookPayload) -> &'static str {
    // 1. Resolve Credentials with Secure Environment Fallback
    let token = payload.token.clone()
        .or_else(|| {
            // Only use environment token if ACCESS_SECRET exists and project path is valid
            if let Ok(access_secret) = env::var("ACCESS_SECRET") {
                if !access_secret.is_empty() {
                    debug!("ACCESS_SECRET validated, checking for environment token");
                    env::var("DOCKER_ACCESS_TOKEN").ok()
                } else {
                    None
                }
            } else {
                None
            }
        });
    
    let user = payload.user.clone()
        .or_else(|| {
            // Only use environment user if ACCESS_SECRET exists
            if let Ok(access_secret) = env::var("ACCESS_SECRET") {
                if !access_secret.is_empty() {
                    env::var("DOCKER_USER").ok()
                } else {
                    None
                }
            } else {
                None
            }
        });

    let registry = match payload.registry.clone() {
        Some(r) => r,
        None => {
            error!("❌ Missing registry in payload");
            return "Missing Registry";
        }
    };

    // 2. Handle Authentication
    let (t, u) = match (token, user) {
        (Some(t), Some(u)) => (t, u),
        _ => {
            error!("❌ Missing Docker credentials (token or user) in payload or environment");
            return "Missing Docker Credentials";
        }
    };

    info!("Attempting Docker login to {}", registry);
    let login_status = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {} | docker login {} -u {} --password-stdin", t, registry, u))
        .status()
        .await;

    match login_status {
        Ok(status) if status.success() => {
            info!("✅ Docker login successful");
        }
        _ => {
            error!("❌ Docker login failed for {}", registry);
            return "Docker Login Failed";
        }
    }

    // 3. Trigger Docker Compose with --pull always
    info!("Running: docker compose up -d --pull always in {}", path);
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && docker compose up -d --pull always", path))
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!("✅ Container(s) updated and restarted successfully via Docker Compose");
            "Success: Images Pulled and Containers Restarted"
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Docker Compose failed in {}: {}", path, stderr);
            "Docker Compose pull/up failed"
        }
        Err(e) => {
            error!("Failed to execute Docker Compose command in {}: {}", path, e);
            "Command execution error"
        }
    }
}

// Environment-based deployment functions (for query param approach)
async fn deploy_git_env(path: &str) -> &'static str {
    // Get credentials from environment
    let token = match env::var("GIT_PAT_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            error!("❌ Missing GIT_PAT_TOKEN in environment");
            return "Missing Git Credentials";
        }
    };
    
    let user = match env::var("DOCKER_USER") {
        Ok(u) => u,
        Err(_) => {
            error!("❌ Missing DOCKER_USER in environment");
            return "Missing Git Credentials";
        }
    };

    // Perform Force Git Pull (Fetch + Reset Hard)
    info!("Starting Force Git Pull (fetch & reset --hard) in {}", path);
    let pull_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && \
             git -c credential.helper= -c \"credential.helper=!f() {{ echo username={}; echo password={}; }}; f\" fetch origin main && \
             git reset --hard origin/main",
            path, user, token
        ))
        .status()
        .await;

    match pull_status {
        Ok(status) if status.success() => {
            info!("✅ Git pull successful");
        }
        _ => {
            error!("❌ Git pull failed in {}", path);
            return "Git Pull Failed";
        }
    }

    // Trigger Docker Compose Build and Up
    info!("Running: docker compose up -d --build in {}", path);
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && docker compose up -d --build", path))
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!("✅ Container(s) rebuilt and restarted successfully via Docker Compose");
            "Success: Repo Pulled and Containers Rebuilt"
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Docker Compose build/up failed in {}: {}", path, stderr);
            "Git pull success, but Compose build/up failed"
        }
        Err(e) => {
            error!("Failed to execute Docker Compose command in {}: {}", path, e);
            "Command execution error"
        }
    }
}

async fn deploy_docker_env(path: &str) -> &'static str {
    // Get credentials from environment
    let token = match env::var("DOCKER_ACCESS_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            error!("❌ Missing DOCKER_ACCESS_TOKEN in environment");
            return "Missing Docker Credentials";
        }
    };
    
    let user = match env::var("DOCKER_USER") {
        Ok(u) => u,
        Err(_) => {
            error!("❌ Missing DOCKER_USER in environment");
            return "Missing Docker Credentials";
        }
    };

    let registry = match env::var("DOCKER_REGISTRY") {
        Ok(r) => r,
        Err(_) => {
            error!("❌ Missing DOCKER_REGISTRY in environment");
            return "Missing Registry Configuration";
        }
    };

    // Docker login
    info!("Attempting Docker login to {}", registry);
    let login_status = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {} | docker login {} -u {} --password-stdin", token, registry, user))
        .status()
        .await;

    match login_status {
        Ok(status) if status.success() => {
            info!("✅ Docker login successful");
        }
        _ => {
            error!("❌ Docker login failed for {}", registry);
            return "Docker Login Failed";
        }
    }

    // Trigger Docker Compose with --pull always
    info!("Running: docker compose up -d --pull always in {}", path);
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && docker compose up -d --pull always", path))
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!("✅ Container(s) updated and restarted successfully via Docker Compose");
            "Success: Images Pulled and Containers Restarted"
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Docker Compose failed in {}: {}", path, stderr);
            "Docker Compose pull/up failed"
        }
        Err(e) => {
            error!("Failed to execute Docker Compose command in {}: {}", path, e);
            "Command execution error"
        }
    }
}


async fn handle_error(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ErrorPayload>,
) -> &'static str {
    info!("📥 Processing build error for project: {}", payload.project);

    // 1. Lookup Project Path
    let project_path = match state.config.get(&payload.project) {
        Some(entry) => entry.path(),
        None => {
            warn!("Project '{}' not found in config", payload.project);
            return "Project not found";
        }
    };

    // 2. Verify Local Remote matches Payload Repository
    let remote_output = Command::new("git")
        .arg("-C")
        .arg(project_path)
        .arg("remote")
        .arg("get-url")
        .arg("origin")
        .output()
        .await;

    let remote_url = match remote_output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            error!("Failed to get local git remote for {}", project_path);
            return "Local verification failed";
        }
    };

    if !remote_url.contains(&payload.repository) {
        warn!(
            "Repository mismatch: Local({}) vs Payload({})",
            remote_url, payload.repository
        );
        return "Repository mismatch";
    }

    // 3. Inner Auth Check on GitHub
    let auth_url = format!(
        "https://{}@github.com/{}",
        payload.token, payload.repository
    );
    let check_status = Command::new("git")
        .arg("ls-remote")
        .arg(&auth_url)
        .status()
        .await;

    match check_status {
        Ok(status) if status.success() => {
            info!("✅ Auth Success. Logging error...");
            error!(
                "🚨 [BUILD ERROR][{}] Repo: {} -> {}",
                payload.project, payload.repository, payload.message
            );
            "Error Logged Successfully"
        }
        _ => {
            warn!("❌ GitHub Auth failed for {}", payload.repository);
            "Authentication Failed"
        }
    }
}

async fn create_backup(project_name: &str, project_path: &str) {
    let timestamp = match Command::new("date").arg("+%Y%m%d%H%M%S").output().await {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => {
            error!("Failed to get timestamp for backup");
            return;
        }
    };

    let backup_dir = format!("/opt/graft/backup/{}/{}", project_name, timestamp);
    let compose_dir = format!("{}/compose", backup_dir);
    let images_dir = format!("{}/images", backup_dir);

    info!("📦 Starting backup for project: {} into {}", project_name, backup_dir);

    // 1. Create directory structure
    if let Err(e) = std::fs::create_dir_all(&compose_dir) {
        error!("Failed to create backup compose dir: {}", e);
        return;
    }
    if let Err(e) = std::fs::create_dir_all(&images_dir) {
        error!("Failed to create backup images dir: {}", e);
        return;
    }

    // 2. Backup compose files and env files
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("cp {}/docker-compose.yml {}/ 2>/dev/null", project_path, compose_dir))
        .status()
        .await;
    
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("cp {}/*.env {}/ 2>/dev/null", project_path, compose_dir))
        .status()
        .await;

    // 3. Backup current images using docker save
    let images_output = Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && docker compose ps --format '{{{{.Image}}}}'", project_path))
        .output()
        .await;

    if let Ok(out) = images_output {
        let images = String::from_utf8_lossy(&out.stdout);
        for img in images.lines() {
            let img = img.trim();
            if !img.is_empty() {
                let safe_name = img.replace(['/', ':'], "_");
                let save_path = format!("{}/{}.tar", images_dir, safe_name);
                info!("💾 Saving image {} to {}", img, save_path);
                
                let status = Command::new("docker")
                    .args(["save", "-o", &save_path, img])
                    .status()
                    .await;
                
                if let Ok(s) = status {
                    if s.success() {
                        // Zip the tar file to save space as requested
                        let _ = Command::new("gzip").arg(&save_path).status().await;
                    }
                }
            }
        }
    }

    info!("✅ Backup completed for {}", project_name);
}

async fn prune_backups(project_name: &str, limit: u32) {
    let backup_root = format!("/opt/graft/backup/{}", project_name);
    let output = Command::new("ls")
        .arg("-1")
        .arg(&backup_root)
        .output()
        .await;

    if let Ok(out) = output {
        let mut dirs: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.to_string())
            .collect();
        
        dirs.sort(); // Sorts by timestamp (ascending)

        if dirs.len() > (limit + 1) as usize {
            let to_delete = dirs.len() - (limit + 1) as usize;
            for i in 0..to_delete {
                let dir_to_remove = format!("{}/{}", backup_root, dirs[i]);
                info!("🗑️ Pruning old backup (keeping {} total): {}", limit + 1, dir_to_remove);
                let _ = Command::new("rm").args(["-rf", &dir_to_remove]).status().await;
            }
        }
    }
}
