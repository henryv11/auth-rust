use crate::{
    auth::Claims,
    database::Pool,
    domains::{
        auth::repository::{create_user, find_user_by_credentials, find_user_by_id, User},
        session::{
            repository::Session,
            service::{get_active_session, get_active_session_by_token, get_new_session},
        },
    },
    error::Error,
    request_data::RequestData,
};
use bcrypt::{hash, DEFAULT_COST};
use chrono::{prelude::Utc, Duration};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

pub async fn handle_registration(
    pool: &Pool,
    request_data: &RequestData,
    credentials: &Credentials,
) -> Result<(User, Session, String), Error> {
    let encrypted_password = hash(&credentials.password, DEFAULT_COST)?;
    let user = create_user(pool, &credentials.username, &encrypted_password).await?;
    let session = get_new_session(pool, request_data, &user.id, &None).await?;
    let jwt = get_jwt(&user.id, &vec![], &session.token)?;
    Ok((user, session, jwt))
}

pub async fn handle_login(
    pool: &Pool,
    request_data: &RequestData,
    credentials: &Credentials,
) -> Result<(User, Session, String), Error> {
    let encrypted_password = hash(&credentials.password, DEFAULT_COST)?;
    let user = find_user_by_credentials(pool, &credentials.username, &encrypted_password)
        .await
        .map_err(|error| match error {
            Error::NotFound => Error::InvalidCredentials,
            _ => error,
        })?;
    let session = get_active_session(pool, request_data, &user.id).await?;
    let jwt = get_jwt(&user.id, &vec![], &session.token)?;
    Ok((user, session, jwt))
}

pub async fn handle_session_refresh(
    pool: &Pool,
    request_data: &RequestData,
    claims: &Claims,
) -> Result<(User, Session, String), Error> {
    let user = find_user_by_id(pool, &claims.sub)
        .await
        .map_err(|error| match error {
            Error::NotFound => Error::InvalidCredentials,
            _ => error,
        })?;
    let session = get_active_session_by_token(pool, request_data, &claims.stk, &claims.sub).await?;
    let jwt = get_jwt(&user.id, &vec![], &session.token)?;
    Ok((user, session, jwt))
}

fn get_jwt(sub: &i64, roles: &Vec<String>, session_token: &String) -> Result<String, Error> {
    // TODO: keep in memory
    let jwt_header = Header {
        // TODO: figure out a kid
        kid: Some("".to_owned()),
        ..Header::new(Algorithm::RS512)
    };
    // TODO: proper private key + keep in memory
    let private_key = EncodingKey::from_rsa_pem(b"").map_err(|_| Error::InternalServerError)?;

    let claims = Claims {
        stk: session_token.to_owned(),
        sub: sub.to_owned(),
        roles: roles.to_owned(),
        exp: Utc::now()
            .checked_add_signed(Duration::minutes(5))
            .expect("valid timestamp")
            .timestamp(),
        iat: Utc::now().timestamp(),
        iss: "@heviir/auth-service".to_owned(),
    };
    encode(&jwt_header, &claims, &private_key).map_err(|_| Error::InternalServerError)
}
