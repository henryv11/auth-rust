use actix_web::error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An internal error occured. Please try again later.")]
    PoolError(deadpool_postgres::PoolError),
    #[error("An internal error occured. Please try again later.")]
    DatabaseError(tokio_postgres::Error),
    #[error("Failed to hash password.")]
    BcryptError(bcrypt::BcryptError),
    #[error("Invalid username or password.")]
    InvalidCredentialsError,
    #[error("Not found")]
    NotFoundError,
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(error: deadpool_postgres::PoolError) -> Self {
        Self::PoolError(error)
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::DatabaseError(error)
    }
}

impl From<bcrypt::BcryptError> for Error {
    fn from(error: bcrypt::BcryptError) -> Self {
        Self::BcryptError(error)
    }
}

impl error::ResponseError for Error {}
