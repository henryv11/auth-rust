use r2d2::Pool;
use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};

pub type ConnectionPool = Pool<PostgresConnectionManager<r2d2_postgres::postgres::NoTls>>;

pub fn pool() -> ConnectionPool {
    let manager = PostgresConnectionManager::new(
        "host=localhost port=5432 user=postgres password=postgres dbname=auth"
            .parse()
            .unwrap(),
        NoTls,
    );
    Pool::new(manager).unwrap()
}
