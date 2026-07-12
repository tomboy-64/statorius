mod app;
mod net;
mod state;

use app::PingApp;
use state::SharedState;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // Commands (Start/Stop/Delete) flow UI -> worker over this channel.
    let (tx_req, rx_req) = mpsc::channel::<state::WorkerCommand>(100);

    // Results flow worker -> UI through shared state instead of a channel:
    // the worker writes into it, the UI reads a snapshot every frame.
    let shared_state = SharedState::new();

    tokio::spawn(net::ping_worker(rx_req, shared_state.clone()));

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Network Ping Tool",
        options,
        Box::new(|_cc| Ok(Box::new(PingApp::new(tx_req, shared_state)))),
    )
}