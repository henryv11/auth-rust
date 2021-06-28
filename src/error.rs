use crate::auth::Error as AuthError;
use actix_web::error::ResponseError;
use bcrypt::BcryptError;
use deadpool_postgres::PoolError;
use thiserror::Error as ThisError;
use tokio_postgres::Error as PostgresError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("An internal error occured. Please try again later.")]
    Pool(PoolError),
    #[error("An internal error occured. Please try again later.")]
    Database(PostgresError),
    #[error("Failed to hash password.")]
    Encryption(BcryptError),
    #[error("Invalid username or password.")]
    InvalidCredentials,
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized(AuthError),
    #[error("Internal server error")]
    InternalServerError,
    #[error("Two factor authentication required")]
    TwoFactorAuthRequired,
}

impl From<PoolError> for Error {
    fn from(error: PoolError) -> Self {
        Self::Pool(error)
    }
}

impl From<PostgresError> for Error {
    fn from(error: PostgresError) -> Self {
        Self::Database(error)
    }
}

impl From<BcryptError> for Error {
    fn from(error: BcryptError) -> Self {
        Self::Encryption(error)
    }
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Self::Unauthorized(error)
    }
}

impl ResponseError for Error {}
