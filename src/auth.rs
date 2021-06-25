use actix_web::{
    dev::Payload, error::ResponseError, http::HeaderMap, web::Data, FromRequest, HttpRequest,
};
use futures::future::{ok, Ready};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone)]
pub enum Error {
    #[error("Missing authorization header")]
    MissingHeaderError,
    #[error("Invalid authorization header")]
    InvalidHeaderError,
    #[error("Invalid token")]
    InvalidTokenError,
    #[error("Failed to encode token")]
    TokenEncodingError,
    #[error("User not in role")]
    NotInRoleError,
    #[error("User does not have permission to operate on resource")]
    NotAllowedError,
    #[error("Unknown error")]
    UnknownError,
    #[error("Invalid configuration")]
    ConfigurationError,
}

pub enum Operation {
    Create,
    Read,
    Update,
    Delete,
}

impl ResponseError for Error {}

#[derive(Debug, Deserialize, Serialize)]
pub struct PermissionMatrixEntry {
    create: Vec<String>,
    read: Vec<String>,
    update: Vec<String>,
    delete: Vec<String>,
}

impl PermissionMatrixEntry {
    fn is_allowed_to(&self, user_role: &str, operation: &Operation) -> bool {
        match operation {
            Operation::Create => &self.create,
            Operation::Read => &self.create,
            Operation::Update => &self.create,
            Operation::Delete => &self.delete,
        }
        .iter()
        .any(|role| role == user_role)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub stk: String,
    pub sub: i64,
    pub roles: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
}

pub struct Auth {
    claims: Option<Claims>,
    error: Option<Error>,
    permission_matrix: HashMap<String, PermissionMatrixEntry>,
}

impl Auth {
    fn from_error(error: Error) -> Self {
        Auth {
            claims: None,
            error: Some(error),
            permission_matrix: HashMap::new(),
        }
    }

    fn from_claims(claims: Claims) -> Self {
        Auth {
            claims: Some(claims),
            error: None,
            permission_matrix: HashMap::new(),
        }
    }

    pub fn assert_has_token(&self) -> Result<&Claims, Error> {
        let Auth { claims, error, .. } = self;
        match claims {
            Some(claims) => Ok(claims),
            None => match error {
                Some(error) => Err(*error),
                None => Err(Error::UnknownError),
            },
        }
    }

    pub fn assert_has_role(&self, role: &str) -> Result<&Claims, Error> {
        let claims = self.assert_has_token()?;
        match claims.roles.iter().find(|user_role| *user_role == role) {
            Some(_) => Ok(claims),
            None => Err(Error::NotInRoleError),
        }
    }

    pub fn assert_has_permission(
        &self,
        resource: &str,
        operation: &Operation,
    ) -> Result<&Claims, Error> {
        let claims = self.assert_has_token()?;
        let permission_matrix_entry = self.permission_matrix.get(resource);
        if permission_matrix_entry.is_none() {
            return Err(Error::ConfigurationError);
        }
        let permission_matrix_entry = permission_matrix_entry.unwrap();
        match claims
            .roles
            .iter()
            .any(|role| permission_matrix_entry.is_allowed_to(role, operation))
        {
            true => Ok(claims),
            false => Err(Error::NotAllowedError),
        }
    }
}

impl FromRequest for Auth {
    type Error = Error;
    type Future = Ready<Result<Auth, Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_decoder = req.app_data::<Data<dyn JsonWebTokenDecoder>>();
        if jwt_decoder.is_none() {
            return ok(Auth::from_error(Error::ConfigurationError));
        }
        let token = get_token(req.headers());
        if token.is_err() {
            return ok(Auth::from_error(token.unwrap_err()));
        }
        match jwt_decoder.unwrap().decode(token.unwrap()) {
            Ok(claims) => ok(Auth::from_claims(claims)),
            Err(error) => ok(Auth::from_error(error)),
        }
    }
}

pub trait JsonWebTokenDecoder {
    fn decode(&self, raw_token: &str) -> Result<Claims, Error>;
}

fn get_token(headers: &HeaderMap) -> Result<&str, Error> {
    let token_header = headers.get("Authorization");
    if token_header.is_none() {
        return Err(Error::MissingHeaderError);
    }
    let token_header = token_header
        .unwrap()
        .to_str()
        .map_err(|_| Error::InvalidHeaderError)?;
    let parts = token_header.split_whitespace().collect::<Vec<&str>>();
    if parts.get(0).unwrap().to_owned() != "Bearer" || parts.get(1).is_none() {
        return Err(Error::InvalidHeaderError);
    }
    Ok(parts.get(1).unwrap())
}
