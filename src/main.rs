use actix_web::{App, HttpServer};

pub mod database;
pub mod domains;
pub mod error;
pub mod jwt;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .data(database::pool())
            .configure(domains::configure)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
