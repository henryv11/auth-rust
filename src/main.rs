use actix_web::{App, HttpServer};

mod database;
mod domains;

pub struct AppState {
    pub database: database::ConnectionPool,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .data(AppState {
                database: database::pool(),
            })
            .configure(domains::configure)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
