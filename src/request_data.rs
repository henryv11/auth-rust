use actix_web::{dev::Payload, error::ResponseError, FromRequest, HttpRequest};
use futures::future::{ok, Ready};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {}
impl ResponseError for Error {}

pub struct RequestData {
    pub ip: Option<String>,
    pub agent: Option<String>,
}

impl FromRequest for RequestData {
    type Error = Error;
    type Future = Ready<Result<RequestData, Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let ip = match req.peer_addr() {
            Some(peer_addr) => Some(peer_addr.ip().to_string()),
            _ => None,
        };
        let agent = match req.headers().get("Agent") {
            Some(agent_header) => match agent_header.to_str() {
                Ok(agent) => Some(agent.to_owned()),
                _ => None,
            },
            _ => None,
        };
        ok(RequestData { ip, agent })
    }
}
