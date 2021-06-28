use crate::{
    database::{Pool, Row},
    error::Error,
};
use chrono::{serde::ts_milliseconds::serialize as to_ts, DateTime, Utc};
use serde::Serialize;

#[derive(Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(serialize_with = "to_ts")]
    pub created_at: DateTime<Utc>,
}

impl User {
    fn from_row(row: &Row) -> Self {
        User {
            id: row.get(0),
            username: row.get(1),
            created_at: row.get(2),
        }
    }
}

pub async fn create_user(pool: &Pool, username: &String, password: &String) -> Result<User, Error> {
    let client = pool.get().await?;
    let row = &client
        .query(
            "INSERT INTO auth_user (username, password)
                      VALUES ($1, $2)
                      RETURNING id, username, created_at",
            &[username, password],
        )
        .await?[0];
    Ok(User::from_row(row))
}

pub async fn find_user_by_credentials(
    pool: &Pool,
    username: &String,
    password: &String,
) -> Result<User, Error> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, username, created_at
                      FROM auth_user
                      WHERE username = $1 AND password = $2",
            &[username, password],
        )
        .await?;
    if rows.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(User::from_row(&rows[0]))
    }
}

pub async fn find_user_by_id(pool: &Pool, id: &i64) -> Result<User, Error> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, username, created_at
                      FROM auth_user
                      WHERE id = $1",
            &[id],
        )
        .await?;
    if rows.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(User::from_row(&rows[0]))
    }
}
