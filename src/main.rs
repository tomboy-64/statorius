mod app;
mod net;
mod state;

use app::PingApp;
use state::SharedState;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // Dual-mode binary: `kammer-pinger --l2-helper <endpoint>` is not the
    // GUI at all - it's the (possibly elevated) L2 helper process, spawned
    // by `net::l2_manager` when the user checks "L2 mode". This is checked
    // before touching anything GUI-related, since the helper never opens a
    // window.
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--l2-helper") {
        match args.get(pos + 1) {
            Some(endpoint) => net::l2_helper::run_l2_helper(endpoint.clone()).await,
            None => eprintln!("--l2-helper requires an endpoint name argument"),
        }
        return Ok(());
    }

    // Commands (Start/Stop/Delete) flow UI -> worker over this channel.
    let (tx_req, rx_req) = mpsc::channel::<state::WorkerCommand>(100);

    // Results flow worker -> UI through shared state instead of a channel:
    // the worker writes into it, the UI reads a snapshot every frame.
    let shared_state = SharedState::new();

    tokio::spawn(net::ping_worker(rx_req, shared_state.clone()));

    // One-time, side-effect-free check of whether raw L2 work is already
    // possible as launched - never tries to acquire privileges itself. See
    // `net::l2` for what's actually being checked, and how "impossible
    // outright" is told apart from "possible but needs elevation".
    let l2_readiness = net::l2::probe_l2_readiness();

    // Same shared-state pattern as ping: the UI only ever sends L2Command
    // and reads SharedL2Status. The manager task owns spawning the helper
    // (elevated or not), the IPC handshake, and its whole lifecycle - the
    // GUI process itself never touches a raw socket.
    let (tx_l2, rx_l2) = mpsc::channel::<net::l2_manager::L2Command>(8);
    let l2_status = net::l2_manager::SharedL2Status::new();

    // Separate channel for anything that actually wants to *use* L2 once
    // it's active (ping/duplicate-check jobs) - today that's only the L2
    // pinger list below, but it's the same channel a future TCP/UDP L2 scan
    // would use too. The manager only ever forwards these to the helper
    // while a session is Active; otherwise they fail immediately.
    let (tx_l2_jobs, rx_l2_jobs) = mpsc::channel::<net::l2_manager::L2JobRequest>(32);

    tokio::spawn(net::l2_manager::l2_manager_task(
        rx_l2,
        rx_l2_jobs,
        l2_status.clone(),
        l2_readiness.clone(),
    ));

    // The L2 pinger list itself: same Start/Stop/Delete + shared-state
    // pattern as the plain ping list, just driven over raw L2 instead of
    // regular sockets. The app also gets its own clone of `tx_l2_jobs`
    // directly, to run the live duplicate-check on whatever's currently
    // typed into the "add target" form, independent of any tracked target.
    let (tx_l2_pinger, rx_l2_pinger) = mpsc::channel::<net::l2_pinger::L2PingerCommand>(100);
    let l2_pinger_state = net::l2_pinger::L2PingerState::new();
    tokio::spawn(net::l2_pinger::l2_pinger_worker(
        rx_l2_pinger,
        l2_pinger_state.clone(),
        tx_l2_jobs.clone(),
    ));

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Network Ping Tool",
        options,
        Box::new(|_cc| {
            Ok(Box::new(PingApp::new(
                tx_req,
                shared_state,
                l2_readiness,
                tx_l2,
                l2_status,
                tx_l2_pinger,
                l2_pinger_state,
                tx_l2_jobs,
            )))
        }),
    )
}