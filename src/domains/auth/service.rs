use crate::{
    domains::{
        auth::repository::{create_user, find_user, User},
        session::{
            repository::Session,
            service::{get_active_or_start_new_session, start_new_session},
        },
    },
    error::Error,
    AppData,
};

use bcrypt::{hash, DEFAULT_COST};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

pub async fn register_user(
    data: AppData,
    credentials: Credentials,
) -> Result<(User, Session), Error> {
    let encrypted_password = hash(credentials.password, DEFAULT_COST)?;
    let user = create_user(&data.database, credentials.username, encrypted_password).await?;
    let session = start_new_session(data, user.id).await?;
    Ok((user, session))
}

pub async fn login_user(data: AppData, credentials: Credentials) -> Result<(User, Session), Error> {
    let encrypted_password = hash(credentials.password, DEFAULT_COST)?;
    let user = match find_user(&data.database, credentials.username, encrypted_password).await {
        Ok(user) => Ok(user),
        Err(Error::NotFoundError) => Err(Error::InvalidCredentialsError),
        Err(err) => Err(err),
    }?;
    let session = get_active_or_start_new_session(data, user.id).await?;
    Ok((user, session))
}