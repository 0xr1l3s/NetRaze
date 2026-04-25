use crate::state::AppState;

const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);

pub fn show(ui: &mut egui::Ui, _state: &mut AppState) {
    ui.centered_and_justified(|ui| {
        ui.label(
            egui::RichText::new("🔐 Credential Manager")
                .size(24.0)
                .strong()
                .color(TEXT_DIM),
        );
    });
}
