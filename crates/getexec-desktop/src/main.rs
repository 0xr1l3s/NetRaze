mod app;
mod runtime;
mod state;
mod ui;
mod workflow;
mod workspace;

use app::GetexecDesktopApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Getexec Desktop")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Getexec Desktop",
        options,
        Box::new(|cc| Ok(Box::new(GetexecDesktopApp::new(cc)))),
    )
}
