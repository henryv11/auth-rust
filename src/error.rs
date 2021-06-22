use crate::jwt::Error as JWTError;
use actix_web::error;
use bcrypt::BcryptError;
use deadpool_postgres::PoolError;
use thiserror::Error;
use tokio_postgres::Error as PostgresError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An internal error occured. Please try again later.")]
    PoolError(PoolError),
    #[error("An internal error occured. Please try again later.")]
    DatabaseError(PostgresError),
    #[error("Failed to hash password.")]
    BcryptError(BcryptError),
    #[error("Invalid username or password.")]
    InvalidCredentialsError,
    #[error("Not found")]
    NotFoundError,
    #[error("Unauthorized")]
    UnauthorizedError(JWTError),
}

impl From<PoolError> for Error {
    fn from(error: PoolError) -> Self {
        Self::PoolError(error)
    }
}

impl From<PostgresError> for Error {
    fn from(error: PostgresError) -> Self {
        Self::DatabaseError(error)
    }
}

impl From<BcryptError> for Error {
    fn from(error: BcryptError) -> Self {
        Self::BcryptError(error)
    }
}

impl From<JWTError> for Error {
    fn from(error: JWTError) -> Self {
        Self::UnauthorizedError(error)
    }
}

impl error::ResponseError for Error {}
