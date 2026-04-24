mod app;
mod runtime;
mod state;
mod ui;
mod workflow;
mod workspace;

use app::NetRazeDesktopApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NetRaze Desktop")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "NetRaze Desktop",
        options,
        Box::new(|cc| Ok(Box::new(NetRazeDesktopApp::new(cc)))),
    )
}
