use crate::{error::Error, AppState};
use actix_web::{
    get, post, put,
    web::{Data, Json, ServiceConfig},
    HttpResponse,
};

use serde::Serialize;

pub mod service;

pub mod repository;

use service::{login_user, register_user, Credentials};

#[derive(Serialize)]
pub struct AuthResponse {
    user_id: i64,
    session_token: String,
}

#[put("/")]
pub async fn registration(
    state: Data<AppState>,
    body: Json<Credentials>,
) -> Result<HttpResponse, Error> {
    let (user, session) = register_user(state, body.into_inner()).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
    }))
}

#[post("/")]
pub async fn login(state: Data<AppState>, body: Json<Credentials>) -> Result<HttpResponse, Error> {
    let (user, session) = login_user(state, body.into_inner()).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
    }))
}

#[get("/")]
pub async fn refresh() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().finish())
}

pub fn configure(config: &mut ServiceConfig) {
    config.service(registration);
    config.service(login);
    config.service(refresh);
}
