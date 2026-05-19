use crate::utils::complex::AuthHeader;
use rocket::http::CookieJar;

/// #[rocket::get("/example?<key>")]
/// pub async fn example(
///     key: Option<String>,
///     auth_header: AuthHeader,
///     cookies: &CookieJar<'_>,
/// ) -> String {
///     match get_auth_key(key, &auth_header, cookies) {
///         Some(auth_key) => format!("Got key: {}", auth_key),
///         None => "No auth key provided".to_string(),
///     }
/// }
pub fn get_auth_key(
    query_key: Option<String>,
    auth_header: &AuthHeader,
    cookies: &CookieJar<'_>,
) -> Option<String> {
    query_key
        .or_else(|| {
            auth_header.0.clone().and_then(|header| {
                if header.starts_with("Bearer ") {
                    Some(header[7..].to_string())
                } else {
                    Some(header)
                }
            })
        })
        .or_else(|| cookies.get("key").map(|c| c.value().to_string()))
}
