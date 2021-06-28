use crate::{
    database::{Pool, Row},
    error::Error,
};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub ip: Option<String>,
    pub agent: Option<String>,
}

impl Session {
    fn from_row(row: &Row) -> Self {
        Session {
            id: row.get(0),
            user_id: row.get(1),
            token: row.get(2),
            started_at: row.get(3),
            ended_at: row.get(4),
            ip: row.get(5),
            agent: row.get(6),
        }
    }
}

pub async fn create_session(
    pool: &Pool,
    user_id: &i64,
    token: &String,
    ip: &Option<String>,
    agent: &Option<String>,
) -> Result<Session, Error> {
    let client = pool.get().await?;
    let row = &client
        .query(
            "INSERT INTO session (user_id, token, ip, agent)
                      VALUES ($1, $2, $3, $4)
                      RETURNING id, user_id, token, started_at, ended_at, ip, agent",
            &[user_id, token, ip, agent],
        )
        .await?[0];
    Ok(Session::from_row(row))
}

pub async fn find_active_session(pool: &Pool, user_id: &i64) -> Result<Session, Error> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, user_id, token, started_at, ended_at, ip, agent
                      FROM session
                      WHERE user_id = $1 AND ended_at IS NULL
                      LIMIT 1",
            &[user_id],
        )
        .await?;
    match rows.is_empty() {
        true => Err(Error::NotFound),
        false => Ok(Session::from_row(&rows[0])),
    }
}

pub async fn find_active_session_by_token(
    pool: &Pool,
    token: &String,
    user_id: &i64,
) -> Result<Session, Error> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, user_id, token, started_at, ended_at, ip, agent
                      FROM session
                      WHERE token = $1 and user_id = $2 AND ended_at IS NULL
                      LIMIT 1",
            &[token, user_id],
        )
        .await?;
    match rows.is_empty() {
        true => Err(Error::NotFound),
        false => Ok(Session::from_row(&rows[0])),
    }
}

pub async fn update_session_ended_at(
    pool: &Pool,
    session_id: &i64,
    ended_at: &DateTime<Utc>,
) -> Result<Session, Error> {
    let client = pool.get().await?;
    let row = &client
        .query(
            "UPDATE session
                      SET ended_at = $1
                      WHERE id = $2
                      RETURNING id, user_id, token, started_at, ended_at, ip, agent",
            &[ended_at, session_id],
        )
        .await?[0];
    Ok(Session::from_row(row))
}

pub async fn find_sessions_by_request_data(
    pool: &Pool,
    user_id: &i64,
    ip: &Option<String>,
    agent: &Option<String>,
) -> Result<Vec<Session>, Error> {
    let client = pool.get().await?;
    let rows = &client
        .query(
            "SELECT id, user_id, token, started_at, ended_at, ip, agent
                      FROM session
                      WHERE user_id = $1
                      AND (ip IS NOT NULL AND ip = COALESCE($2, ip))
                      AND (agent IS NOT NULL AND agent = COALESCE($3, agent))",
            &[user_id, ip, agent],
        )
        .await?;
    if rows.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(rows.iter().map(|row| Session::from_row(row)).collect())
    }
}
