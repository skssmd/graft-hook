use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use serde_json::json;
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

type ConfigFile = HashMap<String, String>;

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

    println!("{}", payload);
    // 1. Lookup Project Path
    let project_path = match state.config.get(&payload.project) {
        Some(path) => {
            debug!("Project matched: Path is {}", path);
            path
        },
        None => {
            error!("Project '{}' not found in config", payload.project);
            return "Project not found in config";
        }
    };

    // 2. Select Deployment Mode
    match payload.r#type.as_str() {
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
    }
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

    // 2. Perform Git Pull with token using credential helper
    // We use a temporary credential helper to pass the token without changing the remote URL
    info!("Starting Git pull in {}", path);
    let pull_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && git -c credential.helper= -c \"credential.helper=!f() {{ echo username={}; echo password={}; }}; f\" pull origin main",
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
        Some(path) => path,
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
