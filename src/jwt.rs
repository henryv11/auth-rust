use actix_web::{dev::Payload, error::ResponseError, http::HeaderMap, FromRequest, HttpRequest};
use chrono::{prelude::Utc, Duration};
use futures::future::{ok, Ready};
use jsonwebtoken::{
    decode, encode, errors::Error as JWTError, Algorithm, DecodingKey, EncodingKey, Header,
    TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing authorization header")]
    MissingHeaderError,
    #[error("Invalid authorization header")]
    InvalidHeaderError,
    #[error("Invalid token")]
    InvalidTokenError(JWTError),
    #[error("Failed to encode token")]
    TokenEncodingError(JWTError),
    #[error("User not in role")]
    NotInRoleError,
    #[error("Unknown error")]
    UnknownError,
}

impl ResponseError for Error {}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    sub: i64,
    roles: Vec<String>,
    exp: usize,
}

pub struct Config {}

impl Default for Config {
    fn default() -> Self {
        Config {}
    }
}

pub struct Auth {
    claims: Option<Claims>,
    error: Option<Error>,
    // jwt: JsonWebToken<[u8]>,
}

impl Auth {
    pub fn assert_is_logged_in(&self) -> Result<&Claims, &Error> {
        let Auth { claims, error, .. } = self;
        match claims {
            Some(claims) => Ok(claims),
            None => match error {
                Some(error) => Err(error),
                None => Err(&Error::UnknownError),
            },
        }
    }

    pub fn assert_has_role(&self, role: &String) -> Result<(), &Error> {
        let claims = self.assert_is_logged_in()?;
        match claims.roles.iter().find(|user_role| *user_role == role) {
            Some(_) => Ok(()),
            None => Err(&Error::NotInRoleError),
        }
    }
}

impl FromRequest for Auth {
    type Error = Error;
    type Future = Ready<Result<Auth, Error>>;
    type Config = Config;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match get_token_data(req) {
            Ok(token_data) => ok(Auth {
                claims: Some(token_data.claims),
                error: None,
            }),
            Err(error) => ok(Auth {
                claims: None,
                error: Some(error),
            }),
        }
    }

    fn configure<F>(f: F) -> Self::Config
    where
        F: FnOnce(Self::Config) -> Self::Config,
    {
        f(Self::Config::default())
    }
}

fn get_token_data(req: &HttpRequest) -> Result<TokenData<Claims>, Error> {
    let raw_token = get_token(req.headers())?;
    decode_token(&raw_token)
}

fn get_token(headers: &HeaderMap) -> Result<String, Error> {
    match headers.get("Authorization") {
        Some(token_header) => match token_header.to_str() {
            Ok(raw_token) => {
                let parts: Vec<&str> = raw_token.split(" ").collect();
                match parts.get(1) {
                    Some(token) => Ok(String::from(token.to_owned())),
                    None => Err(Error::InvalidHeaderError),
                }
            }
            Err(_) => Err(Error::InvalidHeaderError),
        },
        None => Err(Error::MissingHeaderError),
    }
}

#[allow(dead_code)]
struct JsonWebToken<'a> {
    private_key: EncodingKey,
    public_key: DecodingKey<'a>,
}

#[allow(dead_code)]
impl JsonWebToken<'_> {
    pub fn from_secrets(private: &[u8], public: &[u8]) -> Self {
        JsonWebToken {
            private_key: EncodingKey::from_secret(private),
            public_key: DecodingKey::from_secret(public),
        }
    }

    pub fn decode_token(&self, token: &String) -> Result<TokenData<Claims>, Error> {
        decode::<Claims>(token, &self.public_key, &Validation::new(Algorithm::HS512))
            .map_err(|error| Error::InvalidTokenError(error))
    }

    pub fn encode_token(&self, sub: &i64, roles: &Vec<String>) -> Result<String, Error> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(5))
            .expect("valid timestamp")
            .timestamp();

        let claims = Claims {
            sub: sub.to_owned(),
            roles: roles.to_owned(),
            exp: expiration as usize,
        };

        encode(&Header::new(Algorithm::HS512), &claims, &self.private_key)
            .map_err(|err| Error::TokenEncodingError(err))
    }
}

fn decode_token(token: &String) -> Result<TokenData<Claims>, Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(b""),
        &Validation::new(Algorithm::HS512),
    )
    .map_err(|error| Error::InvalidTokenError(error))
}

fn encode_token(sub: &i64, roles: &Vec<String>) -> Result<String, Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(5))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: sub.to_owned(),
        roles: roles.to_owned(),
        exp: expiration as usize,
    };

    let g = EncodingKey::from_secret(b"");

    encode(
        &Header::new(Algorithm::HS512),
        &claims,
        &EncodingKey::from_secret(b""),
    )
    .map_err(|err| Error::TokenEncodingError(err))
}
