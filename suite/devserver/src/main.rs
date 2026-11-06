//! `arkhon-suite-dev`: run the suite prototype against the real engine on this computer.
//!
//! ```text
//! cargo run -p arkhon-suite-dev -- [--port 4317] [--data .arkhon-dev/org.json] [--reset]
//! ```
//! Then open <http://127.0.0.1:4317/dashboard.html#people>.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use arkhon_engine::{demo_state, Store, Suite, SystemClock};
use arkhon_suite_dev::{router, AppState};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut port: u16 = 4317;
    let mut data = PathBuf::from(".arkhon-dev/org.json");
    let mut reset = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().and_then(|p| p.parse().ok()).unwrap_or(port),
            "--data" => data = args.next().map_or(data, PathBuf::from),
            "--reset" => reset = true,
            "--dump-view" => {
                // Engine snapshot for the static preview (embedded in dashboard.html).
                let (seed, ids) = demo_state();
                let suite = Suite::new(seed, Box::new(SystemClock));
                let json =
                    serde_json::to_string(&suite.view(ids.owner)).map_err(std::io::Error::other)?;
                println!("{}", json.replace("</", "<\\/"));
                return Ok(());
            }
            "-h" | "--help" => {
                println!("arkhon-suite-dev [--port N] [--data FILE] [--reset] [--dump-view]");
                return Ok(());
            }
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }
    let store = Store::new(&data);
    let (seed, ids) = demo_state();
    let saved = if reset { None } else { store.load()? };
    let state = if let Some(saved) = saved {
        saved
    } else {
        store.save(&seed)?;
        seed
    };
    let static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app/design");
    let app = router(
        AppState::new(
            Suite::new(state, Box::new(SystemClock)),
            Some(store),
            ids.owner,
        ),
        static_dir,
        port,
    );
    // Loopback only: this dev server trusts the x-arkhon-as header.
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!(
        "Arkhon dev server: http://{addr}/dashboard.html#people  (data: {})",
        data.display()
    );
    axum::serve(listener, app).await
}
