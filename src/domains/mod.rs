use actix_web::web::ServiceConfig;

mod auth;

pub fn configure(config: &mut ServiceConfig) {
    auth::configure(config);
}
