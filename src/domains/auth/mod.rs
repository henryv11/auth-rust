use actix_web::{
    get, post, put,
    web::{Data, ServiceConfig},
    HttpResponse, Responder,
};

use super::super::AppState;

#[put("/")]
async fn registration(_data: Data<AppState>) -> impl Responder {
    let db_client = _data.as_ref().database.get().unwrap();

    HttpResponse::Ok()
}

#[post("/")]
async fn login() -> impl Responder {
    HttpResponse::Ok()
}

#[get("/")]
async fn refresh() -> impl Responder {
    HttpResponse::Ok()
}

pub fn configure(config: &mut ServiceConfig) {
    config.service(registration);
    config.service(login);
    config.service(refresh);
}
