use std::collections::HashMap;

use anyhow::Result;
use format_bytes::format_bytes;
use rand::Rng;
use reqwest::header::HeaderValue;
use tokio::fs;
use tracing::debug;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let oui_data = fs::read_to_string("oui.json").await.unwrap();
    let oiu_map: HashMap<String, String> = serde_json::from_str(&oui_data).unwrap();
    let oiu_list = oiu_map.keys().cloned().collect::<Vec<String>>();
    debug!("loaded oui data with {} entries", oiu_list.len());

    loop {
        let bssid = random_bssid(&mut rand::thread_rng(), &oiu_list);
        debug!("checking bssid: {}", bssid);
        fetch(&reqwest::Client::new(), &bssid).await.unwrap();
    }
}

fn random_bssid(rng: &mut rand::rngs::ThreadRng, ouis: &[String]) -> String {
    let oui = &ouis[rng.gen_range(0..ouis.len())];
    let mut bssid = String::new();

    bssid.push_str(&(&oui[0..2]).to_lowercase());
    bssid.push_str(":");
    bssid.push_str(&(&oui[3..5]).to_lowercase());
    bssid.push_str(":");
    bssid.push_str(&(&oui[6..8]).to_lowercase());

    for _ in 0..3 {
        bssid.push_str(":");
        bssid.push_str(&format!("{:02x}", rng.gen_range(0..256)));
    }

    bssid
}

async fn fetch(client: &reqwest::Client, bssid: &str) -> Result<()> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert("Accept", HeaderValue::from_static("*/*"));
    headers.insert("Accept-Charset", HeaderValue::from_static("utf-8"));
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip, deflate"));
    headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
    headers.insert(
        "User-Agent",
        HeaderValue::from_static("locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0"),
    );

    let bssid = format_bytes!(b"\x12\x13\n\x11{}\x18\x00\x20\00", bssid.as_bytes());
    let data = format_bytes!(b"\x00\x01\x00\x05en_US\x00\x13com.apple.locationd\x00\x0a8.1.12B411\x00\x00\x00\x01\x00\x00\x00{}{}", bssid.len(), bssid);

    let response = client
        .post("https://gs-loc.apple.com/clls/wloc")
        .headers(headers)
        .body(data)
        .send()
        .await
        .unwrap();

    debug!("got response: {:?}", response);
    let _data = response.bytes().await.unwrap();
    Ok(())
}
