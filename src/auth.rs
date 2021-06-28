use actix_web::{
    dev::Payload, error::ResponseError, http::HeaderMap, web::Data, FromRequest, HttpRequest,
};
use futures::future::{ok, Ready};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug, Copy, Clone)]
pub enum Error {
    #[error("Missing authorization header")]
    MissingHeader,
    #[error("Invalid authorization header")]
    InvalidHeader,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Failed to encode token")]
    TokenEncoding,
    #[error("User not in role")]
    NotInRole,
    #[error("User does not have permission to operate on resource")]
    Unallowed,
    #[error("Unknown error")]
    Unknown,
    #[error("Invalid configuration")]
    InvalidConfiguration,
}

impl ResponseError for Error {}

pub enum Operation {
    Create,
    Read,
    Update,
    Delete,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PermissionMatrixEntry {
    create: Vec<String>,
    read: Vec<String>,
    update: Vec<String>,
    delete: Vec<String>,
}

impl PermissionMatrixEntry {
    fn is_allowed(&self, user_role: &str, operation: &Operation) -> bool {
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
    permission_matrix: Data<HashMap<String, PermissionMatrixEntry>>,
}

impl Auth {
    fn from_error(
        error: Error,
        permission_matrix: Data<HashMap<String, PermissionMatrixEntry>>,
    ) -> Self {
        Auth {
            claims: None,
            error: Some(error),
            permission_matrix,
        }
    }

    fn from_claims(
        claims: Claims,
        permission_matrix: Data<HashMap<String, PermissionMatrixEntry>>,
    ) -> Self {
        Auth {
            claims: Some(claims),
            error: None,
            permission_matrix,
        }
    }

    pub fn assert_has_token(&self) -> Result<&Claims, Error> {
        let Auth { claims, error, .. } = self;
        match claims {
            Some(claims) => Ok(claims),
            None => match error {
                Some(error) => Err(*error),
                None => Err(Error::Unknown),
            },
        }
    }

    pub fn assert_has_role(&self, role: &str) -> Result<&Claims, Error> {
        let claims = self.assert_has_token()?;
        match claims.roles.iter().find(|user_role| *user_role == role) {
            Some(_) => Ok(claims),
            None => Err(Error::NotInRole),
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
            return Err(Error::InvalidConfiguration);
        }
        let permission_matrix_entry = permission_matrix_entry.unwrap();
        match claims
            .roles
            .iter()
            .any(|role| permission_matrix_entry.is_allowed(role, operation))
        {
            true => Ok(claims),
            false => Err(Error::Unallowed),
        }
    }
}

impl FromRequest for Auth {
    type Error = Error;
    type Future = Ready<Result<Auth, Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_decoder = req.app_data::<Data<dyn JsonWebTokenDecoder>>();
        let permission_matrix = req.app_data::<Data<HashMap<String, PermissionMatrixEntry>>>();
        if jwt_decoder.is_none() || permission_matrix.is_none() {
            return ok(Auth::from_error(
                Error::InvalidConfiguration,
                permission_matrix
                    .unwrap_or(&Data::new(HashMap::new()))
                    .clone(),
            ));
        }
        let permission_matrix = permission_matrix.unwrap().clone();
        let token = get_token(req.headers());
        if token.is_err() {
            return ok(Auth::from_error(token.unwrap_err(), permission_matrix));
        }
        match jwt_decoder.unwrap().decode(token.unwrap()) {
            Ok(claims) => ok(Auth::from_claims(claims, permission_matrix)),
            Err(error) => ok(Auth::from_error(error, permission_matrix)),
        }
    }
}

pub trait JsonWebTokenDecoder {
    fn decode(&self, raw_token: &str) -> Result<Claims, Error>;
}

fn get_token(headers: &HeaderMap) -> Result<&str, Error> {
    let token_header = headers.get("Authorization");
    if token_header.is_none() {
        return Err(Error::MissingHeader);
    }
    let token_header = token_header
        .unwrap()
        .to_str()
        .map_err(|_| Error::InvalidHeader)?;
    let parts = token_header.split_whitespace().collect::<Vec<&str>>();
    if parts.get(0).unwrap().to_owned() != "Bearer" || parts.get(1).is_none() {
        return Err(Error::InvalidHeader);
    }
    Ok(parts.get(1).unwrap())
}
