use actix_web::{web::Data, App, HttpServer};

pub mod database;
pub mod domains;
pub mod error;
pub mod jwt;

pub type AppData = Data<AppState>;

pub struct AppState {
    pub database: database::Pool,
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
