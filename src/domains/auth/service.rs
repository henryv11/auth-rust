use crate::{
    auth::Claims,
    database::Pool,
    domains::{
        auth::repository::{
            create_user, find_user_by_id, find_user_by_username_and_password, User,
        },
        session::{
            repository::Session,
            service::{get_active_or_start_new_session, get_session_from_token, start_new_session},
        },
    },
    error::Error,
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

pub async fn register_user(
    pool: &Pool,
    credentials: &Credentials,
) -> Result<(User, Session, String), Error> {
    let encrypted_password = hash(credentials.password, DEFAULT_COST)?;
    let user = create_user(pool, &credentials.username, &encrypted_password).await?;
    let session = start_new_session(pool, &user.id, None).await?;
    let jwt = generate_jwt(&user.id, vec![], &session.token)?;
    Ok((user, session, jwt))
}

pub async fn login_user(
    pool: &Pool,
    credentials: &Credentials,
) -> Result<(User, Session, String), Error> {
    let encrypted_password = hash(credentials.password, DEFAULT_COST)?;
    let user = find_user_by_username_and_password(pool, &credentials.username, &encrypted_password)
        .await
        .map_err(|error| match error {
            Error::NotFoundError => Error::InvalidCredentialsError,
            _ => error,
        })?;
    let session = get_active_or_start_new_session(pool, &user.id).await?;
    let jwt = generate_jwt(&user.id, vec![], &session.token)?;
    Ok((user, session, jwt))
}

pub async fn refresh_user_session(
    pool: &Pool,
    claims: &Claims,
) -> Result<(User, Session, String), Error> {
    let user = find_user_by_id(pool, &claims.sub)
        .await
        .map_err(|error| match error {
            Error::NotFoundError => Error::InvalidCredentialsError,
            _ => error,
        })?;
    let session = get_session_from_token(pool, &claims.stk, &claims.sub).await?;
    let jwt = generate_jwt(&user.id, vec![], &session.token)?;
    Ok((user, session, jwt))
}

const jwt_header: Header = Header {
    kid: Some("".to_owned()),
    ..Header::new(Algorithm::RS512)
};
const private_key: Result<EncodingKey, Error> =
    EncodingKey::from_rsa_pem(b"").map_err(|_| Error::InternalServerError);

fn generate_jwt(sub: &i64, roles: &Vec<String>, session_token: &String) -> Result<String, Error> {
    let claims = Claims {
        stk: session_token.to_string(),
        sub: sub.to_owned(),
        roles: roles.to_owned(),
        exp: Utc::now()
            .checked_add_signed(Duration::minutes(5))
            .expect("valid timestamp")
            .timestamp(),
        iat: Utc::now().timestamp(),
        iss: "@heviir/auth-service".to_owned(),
    };
    encode(&jwt_header, &claims, &private_key?).map_err(|_| Error::InternalServerError)
}
