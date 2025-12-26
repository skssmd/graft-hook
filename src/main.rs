use axum::{extract::State, routing::post, Json, Router};
use bollard::auth::DockerCredentials;
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::stream::StreamExt;
use git2::Repository;
use serde::Deserialize;
use std::{collections::HashMap, env, sync::Arc};
use tokio::process::Command; // Added for running shell commands

#[derive(Deserialize)]
struct WebhookPayload {
    project: String,
    githubtoken: String,
    user: String,
    r#type: String, // "repo" or "image"
}

// Fixed: ConfigFile is now a HashMap to match your "key": "value" JSON structure
type ConfigFile = HashMap<String, String>;

struct AppState {
    config: ConfigFile,
    docker: Docker,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    
    let config_path = env::var("configpath").expect("ENV 'configpath' not set");
    let config_content = std::fs::read_to_string(config_path).expect("Failed to read config");
    
    // Parses directly into a HashMap
    let config: ConfigFile = serde_json::from_str(&config_content)
        .expect("JSON format mismatch: Expected a flat object like { \"name\": \"path\" }");

    let docker = Docker::connect_with_unix_defaults().expect("Failed to connect to Docker");
    let state = Arc::new(AppState { config, docker });

    let app = Router::new().route("/webhook", post(handle_deploy)).with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    
    println!("🚀 Webhook server running on port 3000");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_deploy(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WebhookPayload>,
) -> &'static str {
    // Lookup path from HashMap key
    let project_path = match state.config.get(&payload.project) {
        Some(path) => path,
        None => return "Project not found in config",
    };

    if payload.r#type == "repo" {
        if let Ok(repo) = Repository::open(project_path) {
            let mut remote = repo.find_remote("origin").unwrap();
            remote.fetch(&["main"], None, None).unwrap();
            return "Git Fetch Complete";
        }
    } else if payload.r#type == "image" {
        let auth = DockerCredentials {
            username: Some(payload.user.clone()),
            password: Some(payload.githubtoken.clone()),
            serveraddress: Some("ghcr.io".to_string()),
            ..Default::default()
        };

        // 1. Pull the image
        let mut stream = state.docker.create_image(
            Some(CreateImageOptions { 
                from_image: format!("ghcr.io/{}/{}", payload.user, payload.project), 
                ..Default::default() 
            }),
            None,
            Some(auth),
        );

        while let Some(msg) = stream.next().await {
            if let Err(e) = msg {
                eprintln!("Pull error: {}", e);
                return "Docker Pull Failed";
            }
        }

        // 2. Restart using Docker Compose
        // This executes: cd /path/to/project && docker compose up -d
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("cd {} && docker compose up -d", project_path))
            .status()
            .await;

        return match status {
            Ok(s) if s.success() => "Image Pulled and Container Restarted",
            _ => "Pull success, but Compose restart failed",
        };
    }

    "Invalid Type"
}