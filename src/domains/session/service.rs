use crate::{
    database::Pool,
    domains::session::repository::{
        create_session, find_active_session, find_latest_session_by_token, update_session_ended_at,
        Session,
    },
    error::Error,
};
use chrono::prelude::Utc;

fn generate_session_token() -> String {
    String::new()
}

pub async fn start_new_session(
    pool: &Pool,
    user_id: &i64,
    token: Option<String>,
) -> Result<Session, Error> {
    let token = match token {
        Some(token) => token,
        None => generate_session_token(),
    };
    create_session(pool, user_id, &token).await
}

pub async fn get_active_or_start_new_session(pool: &Pool, user_id: &i64) -> Result<Session, Error> {
    match find_active_session(pool, user_id).await {
        Ok(session) => get_unexpired_session(pool, session).await,
        Err(Error::NotFoundError) => start_new_session(pool, user_id, None).await,
        error => error,
    }
}

pub async fn get_session_from_token(
    pool: &Pool,
    token: &String,
    user_id: &i64,
) -> Result<Session, Error> {
    match find_latest_session_by_token(pool, token, user_id).await {
        Ok(session) => get_unexpired_session(pool, session).await,
        Err(Error::NotFoundError) => Err(Error::InvalidCredentialsError),
        error => error,
    }
}

async fn get_unexpired_session(pool: &Pool, session: Session) -> Result<Session, Error> {
    if Utc::now().timestamp() - session.started_at.timestamp() >= 10 {
        update_session_ended_at(pool, &session.id, &Utc::now()).await?;
        start_new_session(pool, &session.user_id, Some(session.token)).await
    } else {
        Ok(session)
    }
}
