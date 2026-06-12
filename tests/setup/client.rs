use reqwest::{ ClientBuilder, Client };

pub fn get_client() -> reqwest::Client {
    Client::new()
}
