use crate::state::AppState;

const ACCENT: egui::Color32 = egui::Color32::from_rgb(102, 27, 28);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("📊 Progress")
            .size(12.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.add_space(6.0);

    // Progress bar
    let progress = state.progress.clamp(0.0, 1.0);
    let pct = (progress * 100.0) as u32;
    ui.label(
        egui::RichText::new(format!("{pct}%"))
            .monospace()
            .size(22.0)
            .strong()
            .color(if state.is_running { ACCENT } else { TEXT_DIM }),
    );
    ui.add_space(4.0);

    let bar = egui::ProgressBar::new(progress).fill(ACCENT);
    ui.add(bar);
    ui.add_space(4.0);

    if !state.progress_message.is_empty() {
        ui.label(
            egui::RichText::new(&state.progress_message)
                .monospace()
                .size(10.5)
                .color(TEXT_DIM),
        );
    }

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    // Quick stats
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Hosts:").small().color(TEXT_DIM));
        ui.label(
            egui::RichText::new(format!("{}", state.discovered_hosts_count()))
                .small()
                .strong()
                .color(egui::Color32::WHITE),
        );
    });
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Creds:").small().color(TEXT_DIM));
        ui.label(
            egui::RichText::new(format!("{}", state.credentials_count()))
                .small()
                .strong()
                .color(egui::Color32::WHITE),
        );
    });
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Elapsed:").small().color(TEXT_DIM));
        let secs = state.elapsed_seconds();
        ui.label(
            egui::RichText::new(format!("{:02}:{:02}", secs / 60, secs % 60))
                .small()
                .strong()
                .color(egui::Color32::WHITE),
        );
    });

    // Last log line as status
    if let Some(last) = state.logs.last() {
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(&last.message)
                .monospace()
                .size(9.5)
                .color(TEXT_DIM),
        );
    }
}
