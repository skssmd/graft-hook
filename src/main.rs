use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;

use std::{collections::HashMap, env, sync::Arc};
use tokio::process::Command;
use tracing::{info, error, warn, debug, instrument};

#[derive(Deserialize, Debug)]
struct WebhookPayload {
    project: String,
    repository: String,
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

#[instrument(skip(state, payload), fields(project = %payload.project, mode = %payload.r#type))]
async fn handle_deploy(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebhookPayload>,
) -> &'static str {
    info!("📥 Webhook request received");

    debug!("Payload received: {:?}", payload);
    // 1. Lookup Project Path
    let project_entry = match state.config.get(&payload.project) {
        Some(entry) => entry,
        None => {
            error!("Project '{}' not found in config", payload.project);
            return "Project not found in config";
        }
    };

    let project_path = project_entry.path();
    let rollback_limit = project_entry.rollback_backups();

    // 2. Perform Backup if configured
    if rollback_limit > 0 {
        create_backup(&payload.project, project_path).await;
        prune_backups(&payload.project, rollback_limit).await;
    }

    // 3. Select Deployment Mode
    let result = match payload.r#type.as_str() {
        "repo" => {
            info!("Mode selected: Git Pull & Compose Build");
            deploy_git(project_path, &payload).await
        }
        "image" => {
            info!("Mode selected: Docker Login & Compose Pull");
            deploy_docker(project_path, &payload).await
        }
        _ => {
            warn!("Invalid deployment type received: {}", payload.r#type);
            "Invalid Type"
        }
    };

    // 4. Post-deploy cleanup (delete old images safely)
    if result.to_lowercase().contains("success") {
        debug!("Deployment success, performing safe image cleanup");
        let _ = Command::new("docker").args(["image", "prune", "-f"]).status().await;
    }

    result
}

async fn deploy_git(path: &str, payload: &WebhookPayload) -> &'static str {
    // 1. Resolve Credentials with Secure Environment Fallback
    let token = payload.token.clone()
        .or_else(|| {
            // Only use environment token if ACCESS_SECRET exists and project path is valid
            if let Ok(access_secret) = env::var("ACCESS_SECRET") {
                if !access_secret.is_empty() {
                    debug!("ACCESS_SECRET validated, checking for environment token");
                    env::var("DOCKER_TOKEN").ok()
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

async fn deploy_docker(path: &str, payload: &WebhookPayload) -> &'static str {
    // 1. Resolve Credentials with Secure Environment Fallback
    let token = payload.token.clone()
        .or_else(|| {
            // Only use environment token if ACCESS_SECRET exists and project path is valid
            if let Ok(access_secret) = env::var("ACCESS_SECRET") {
                if !access_secret.is_empty() {
                    debug!("ACCESS_SECRET validated, checking for environment token");
                    env::var("DOCKER_TOKEN").ok()
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

    let registry = payload.registry.clone()
        .unwrap_or_else(|| "ghcr.io".to_string());

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

        if dirs.len() > limit as usize {
            let to_delete = dirs.len() - limit as usize;
            for i in 0..to_delete {
                let dir_to_remove = format!("{}/{}", backup_root, dirs[i]);
                info!("🗑️ Pruning old backup: {}", dir_to_remove);
                let _ = Command::new("rm").args(["-rf", &dir_to_remove]).status().await;
            }
        }
    }
}
