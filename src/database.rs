use deadpool_postgres::Manager;
use tokio_postgres::{Config, NoTls};

pub type Pool = deadpool_postgres::Pool;

pub type Client = deadpool_postgres::Client;

pub type Row = tokio_postgres::Row;

pub fn pool() -> Pool {
    let mut config = Config::new();
    config.host("localhost");
    config.port(5432);
    config.dbname("auth");
    config.user("postgres");
    config.password("postgres");
    let manager = Manager::new(config, NoTls);
    Pool::new(manager, 16)
}
