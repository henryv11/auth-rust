use crate::{
    database::Pool,
    domains::session::repository::{
        create_session, find_active_session, find_latest_session_by_token, Session,
    },
    error::Error,
};

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
    let session = create_session(pool, user_id, &token).await?;
    Ok(session)
}

pub async fn get_active_or_start_new_session(pool: &Pool, user_id: &i64) -> Result<Session, Error> {
    let session = match find_active_session(pool, user_id).await {
        Ok(session) => Ok(session),
        Err(Error::NotFoundError) => start_new_session(pool, user_id, None).await,
        Err(error) => Err(error),
    }?;
    Ok(session)
}

pub async fn get_session_from_token(
    pool: &Pool,
    session_token: &String,
    user_id: &i64,
) -> Result<Session, Error> {
    let session = match find_latest_session_by_token(pool, session_token, user_id).await {
        Ok(session) => Ok(session),
        Err(error) => Err(error),
    }?;

    Ok(session)
}

use chrono::prelude::Utc;

async fn get_unexpired_session(pool: &Pool, session: &Session) {
    let diff = Utc::now().timestamp() - session.started_at.timestamp();

    // match session.started_at {}
}

// async fn shit(pool: &Pool, session: &Session) -> Result<Session, Error> {

//     if session.ended_at

//     Ok(session)
// }
