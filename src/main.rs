use axum::{extract::State, routing::post, Json, Router};
use bollard::auth::DockerCredentials;
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::stream::StreamExt;
use git2::Repository;
use serde::Deserialize;
use std::{collections::HashMap, env, sync::Arc};
use tokio::process::Command;
use tracing::{info, error, warn, debug, instrument}; // New imports for logging

#[derive(Deserialize, Debug)] // Added Debug for better payload logging
struct WebhookPayload {
    project: String,
    repository: String,
    githubtoken: String,
    user: String,
    r#type: String,
}

type ConfigFile = HashMap<String, String>;

struct AppState {
    config: ConfigFile,
    docker: Docker,
}

#[tokio::main]
async fn main() {
    // 1. Initialize Logging (Tracing Subscriber)
    tracing_subscriber::fmt()
        .with_target(false) // Keeps logs clean
        .compact()          // One-line logs
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

    let docker = Docker::connect_with_unix_defaults().expect("CRITICAL: Docker connection failed");
    let state = Arc::new(AppState { config, docker });

    let app = Router::new()
        .route("/webhook", post(handle_deploy))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("✅ Server listening on http://0.0.0.0:3000");
    
    axum::serve(listener, app).await.unwrap();
}

// #[instrument] automatically logs the function arguments (excluding sensitive state)
#[instrument(skip(state, payload), fields(project = %payload.project, mode = %payload.r#type))]
async fn handle_deploy(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebhookPayload>,
) -> &'static str {
    info!("📥 Webhook request received");

    // 1. Lookup Project Path
    let project_path = match state.config.get(&payload.project) {
        Some(path) => {
            debug!("Project matched: Path is {}", path);
            path
        },
        None => {
            error!("Project '{}' not found in projects.json", payload.project);
            return "Project not found in config";
        }
    };

    // 2. Select Deployment Mode
    match payload.r#type.as_str() {
        "repo" => {
            info!("Mode selected: Git Pull (Native Git2)");
            deploy_git(project_path).await
        }
        "image" => {
            info!("Mode selected: Docker Pull & Compose (Bollard)");
            deploy_docker(&state.docker, project_path, &payload).await
        }
        _ => {
            warn!("Invalid deployment type received: {}", payload.r#type);
            "Invalid Type"
        }
    }
}

async fn deploy_git(path: &str) -> &'static str {
    match Repository::open(path) {
        Ok(repo) => {
            debug!("Git repository opened successfully");
            let mut remote = repo.find_remote("origin").unwrap();
            if let Err(e) = remote.fetch(&["main"], None, None) {
                error!("Git fetch failed: {}", e);
                return "Git Fetch Failed";
            }
            info!("✅ Git Fetch Complete for {}", path);
            "Git Fetch Complete"
        }
        Err(e) => {
            error!("Failed to open repository at {}: {}", path, e);
            "Repo path error"
        }
    }
}

async fn deploy_docker(docker: &Docker, path: &str, payload: &WebhookPayload) -> &'static str {
    let auth = DockerCredentials {
        username: Some(payload.user.clone()),
        password: Some(payload.githubtoken.clone()),
        serveraddress: Some("ghcr.io".to_string()),
        ..Default::default()
    };

    let image_name = format!(
        "ghcr.io/{}/{}", 
        payload.user.to_lowercase(), 
        payload.repository.to_lowercase()
    );

    info!("Starting image pull: {}", image_name);

    let mut stream = docker.create_image(
        Some(CreateImageOptions { from_image: image_name.clone(), ..Default::default() }),
        None,
        Some(auth),
    );

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(progress) => debug!("Pulling... {:?}", progress.status),
            Err(e) => {
                error!("Docker pull error for {}: {}", image_name, e);
                return "Docker Pull Failed";
            }
        }
    }
    info!("✅ Image pulled successfully");

    // Trigger Docker Compose
    debug!("Executing shell: cd {} && docker compose up -d", path);
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("cd {} && docker compose up -d", path))
        .output() // Use .output() to capture stdout/stderr
        .await;

    match output {
        Ok(out) if out.status.success() => {
            info!("✅ Container restarted successfully via Docker Compose");
            "Image Pulled and Container Restarted"
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Docker Compose failed with status {}: {}", out.status, stderr);
            "Pull success, but Compose restart failed"
        }
        Err(e) => {
            error!("Failed to execute Docker Compose command: {}", e);
            "Command execution error"
        }
    }
}