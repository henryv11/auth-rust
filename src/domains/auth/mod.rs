use crate::{auth::Auth, database::Pool, error::Error};
use actix_web::{
    get, post, put,
    web::{Data, Json, ServiceConfig},
    HttpResponse,
};

use serde::Serialize;

pub mod service;

pub mod repository;

use service::{login_user, refresh_user_session, register_user, Credentials};

#[derive(Serialize)]
pub struct AuthResponse {
    user_id: i64,
    session_token: String,
    jwt: String,
}

#[put("/")]
pub async fn registration(
    pool: Data<Pool>,
    body: Json<Credentials>,
) -> Result<HttpResponse, Error> {
    let (user, session, jwt) = register_user(&pool, &body).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
        jwt,
    }))
}

#[post("/")]
pub async fn login(pool: Data<Pool>, body: Json<Credentials>) -> Result<HttpResponse, Error> {
    let (user, session, jwt) = login_user(&pool, &body).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
        jwt,
    }))
}

#[get("/")]
pub async fn refresh(pool: Data<Pool>, auth: Auth) -> Result<HttpResponse, Error> {
    let claims = auth.assert_has_token()?;
    let (user, session, jwt) = refresh_user_session(&pool, claims).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
        jwt,
    }))
}

pub fn configure(config: &mut ServiceConfig) {
    config.service(registration);
    config.service(login);
    config.service(refresh);
}
