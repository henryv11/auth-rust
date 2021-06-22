use crate::{
    database::{Pool, Row},
    error::Error,
};

pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub started_at: String,
    pub ended_at: Option<String>,
}

impl Session {
    fn from_row(row: &Row) -> Self {
        Session {
            id: row.get(0),
            user_id: row.get(1),
            token: row.get(2),
            started_at: row.get(3),
            ended_at: row.get(4),
        }
    }
}

pub async fn create_session(pool: &Pool, user_id: &i64, token: &String) -> Result<Session, Error> {
    let client = pool.get().await?;
    let row = &client
        .query(
            "INSERT INTO session (user_id, token)
            VALUES ($1, $2)
            RETURNING id, user_id, token, started_at, ended_at",
            &[user_id, token],
        )
        .await?[0];
    Ok(Session::from_row(row))
}

pub async fn find_active_session(pool: &Pool, user_id: &i64) -> Result<Session, Error> {
    let client = pool.get().await?;
    let rows = &client
        .query(
            "SELECT id, user_id, token, started_at, ended_at
            FROM session
            WHERE user_id = $1 AND ended_at = NULL",
            &[user_id],
        )
        .await?;
    match rows.is_empty() {
        true => Err(Error::NotFoundError),
        false => Ok(Session::from_row(&rows[0])),
    }
}
