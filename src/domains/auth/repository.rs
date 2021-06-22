use crate::{
    database::{Pool, Row},
    error::Error,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
}

impl User {
    fn from_row(row: &Row) -> Self {
        User {
            id: row.get(0),
            username: row.get(1),
        }
    }
}

pub async fn create_user(pool: &Pool, username: String, password: String) -> Result<User, Error> {
    let client = pool.get().await?;
    let row = &client
        .query(
            "INSERT INTO auth_user (username, password)
            VALUES ($1, $2)
            RETURNING id, username",
            &[&username, &password],
        )
        .await?[0];
    Ok(User::from_row(row))
}

pub async fn find_user(pool: &Pool, username: String, password: String) -> Result<User, Error> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, username
            FROM auth_user
            WHERE username = $1 AND password = $2",
            &[&username, &password],
        )
        .await?;
    match rows.is_empty() {
        true => Err(Error::NotFoundError),
        false => Ok(User::from_row(&rows[0])),
    }
}
