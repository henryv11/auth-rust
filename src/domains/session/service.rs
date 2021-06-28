use crate::{
    database::Pool,
    domains::session::repository::{
        create_session, find_active_session, find_active_session_by_token,
        find_sessions_by_request_data, update_session_ended_at, Session,
    },
    error::Error,
    request_data::RequestData,
};
use chrono::prelude::Utc;

pub async fn get_new_session(
    pool: &Pool,
    request_data: &RequestData,
    user_id: &i64,
    token: &Option<String>,
) -> Result<Session, Error> {
    let token = match token {
        Some(token) => token.to_owned(),
        None => get_session_token(),
    };
    create_session(pool, user_id, &token, &request_data.ip, &request_data.agent).await
}

pub async fn get_active_session(
    pool: &Pool,
    request_data: &RequestData,
    user_id: &i64,
) -> Result<Session, Error> {
    if !is_valid_request(pool, request_data, user_id).await? {
        return Err(Error::TwoFactorAuthRequired);
    }
    match find_active_session(pool, user_id).await {
        Ok(session) => get_valid_session(pool, request_data, session).await,
        Err(Error::NotFound) => get_new_session(pool, request_data, user_id, &None).await,
        error => error,
    }
}

pub async fn get_active_session_by_token(
    pool: &Pool,
    request_data: &RequestData,
    token: &String,
    user_id: &i64,
) -> Result<Session, Error> {
    if !is_valid_request(pool, request_data, user_id).await? {
        return Err(Error::InvalidCredentials);
    }
    match find_active_session_by_token(pool, token, user_id).await {
        Ok(session) => get_valid_session(pool, request_data, session).await,
        Err(Error::NotFound) => Err(Error::InvalidCredentials),
        error => error,
    }
}

async fn is_valid_request(
    pool: &Pool,
    request_data: &RequestData,
    user_id: &i64,
) -> Result<bool, Error> {
    match find_sessions_by_request_data(pool, user_id, &request_data.ip, &request_data.agent).await
    {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

async fn get_valid_session(
    pool: &Pool,
    request_data: &RequestData,
    session: Session,
) -> Result<Session, Error> {
    if Utc::now().timestamp() - session.started_at.timestamp() >= 43200
        || request_data.ip != session.ip
        || request_data.agent != session.agent
    {
        update_session_ended_at(pool, &session.id, &Utc::now()).await?;
        get_new_session(pool, request_data, &session.user_id, &Some(session.token)).await
    } else {
        Ok(session)
    }
}

fn get_session_token() -> String {
    // TODO: generate a proper token
    String::new()
}
