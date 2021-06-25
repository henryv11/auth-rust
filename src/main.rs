use actix_web::{App, HttpServer};

pub mod auth;
pub mod database;
pub mod domains;
pub mod error;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .data(database::pool())
            // .data(jwt::JsonWebToken::from_secrets(b"", b""))
            .configure(domains::configure)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
