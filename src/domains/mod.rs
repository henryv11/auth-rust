use actix_web::web::ServiceConfig;

pub mod auth;

pub mod session;

pub fn configure(config: &mut ServiceConfig) {
    auth::configure(config);
}
