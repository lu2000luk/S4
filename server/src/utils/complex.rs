use rocket::request::{FromRequest, Outcome, Request};

pub type DBConn = r2d2::PooledConnection<duckdb::DuckdbConnectionManager>;
pub struct AuthHeader(pub Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthHeader {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = request
            .headers()
            .get_one("Authorization")
            .map(|s| s.to_string());
        Outcome::Success(AuthHeader(auth_header))
    }
}
