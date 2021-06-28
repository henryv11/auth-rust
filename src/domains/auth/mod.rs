use crate::{auth::Auth, database::Pool, error::Error, request_data::RequestData};
use actix_web::{
    get, post, put,
    web::{Data, Json, ServiceConfig},
    HttpResponse,
};

use serde::Serialize;

pub mod service;

pub mod repository;

use service::{handle_login, handle_registration, handle_session_refresh, Credentials};

#[derive(Serialize)]
pub struct AuthResponse {
    user_id: i64,
    session_token: String,
    jwt: String,
}

#[put("/")]
pub async fn registration_handler(
    pool: Data<Pool>,
    body: Json<Credentials>,
    request_data: RequestData,
) -> Result<HttpResponse, Error> {
    let (user, session, jwt) = handle_registration(&pool, &request_data, &body).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
        jwt,
    }))
}

#[post("/")]
pub async fn login_handler(
    pool: Data<Pool>,
    body: Json<Credentials>,
    request_data: RequestData,
) -> Result<HttpResponse, Error> {
    let (user, session, jwt) = handle_login(&pool, &request_data, &body).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
        jwt,
    }))
}

#[get("/")]
pub async fn refresh_handler(
    pool: Data<Pool>,
    auth: Auth,
    request_data: RequestData,
) -> Result<HttpResponse, Error> {
    let claims = auth.assert_has_token()?;
    let (user, session, jwt) = handle_session_refresh(&pool, &request_data, claims).await?;
    Ok(HttpResponse::Ok().json(AuthResponse {
        user_id: user.id,
        session_token: session.token,
        jwt,
    }))
}

pub fn configure(config: &mut ServiceConfig) {
    config.service(registration_handler);
    config.service(login_handler);
    config.service(refresh_handler);
}
