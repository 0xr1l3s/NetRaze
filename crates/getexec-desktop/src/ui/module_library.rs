use crate::state::AppState;

const ACCENT: egui::Color32 = egui::Color32::from_rgb(102, 27, 28);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("📦 Modules")
            .size(14.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.label(egui::RichText::new("Drag to canvas").small().color(TEXT_DIM));
    ui.add_space(6.0);

    let categories = state.module_categories.clone();

    egui::ScrollArea::vertical()
        .id_salt("module_library_scroll")
        .show(ui, |ui| {
            for category in &categories {
                let header = egui::RichText::new(format!("▾ {}", category.name))
                    .strong()
                    .color(ACCENT)
                    .size(12.0);
                egui::CollapsingHeader::new(header)
                    .default_open(true)
                    .show(ui, |ui| {
                        for item in &category.items {
                            let is_selected = state.selected_module == *item;
                            let text = egui::RichText::new(format!("  {item}"))
                                .monospace()
                                .size(11.0)
                                .color(if is_selected {
                                    ACCENT
                                } else {
                                    egui::Color32::from_rgb(200, 210, 240)
                                });
                            let response = ui.add(
                                egui::Label::new(text).sense(egui::Sense::click_and_drag()),
                            );

                            if response.clicked() {
                                state.selected_module = item.clone();
                            }
                            if response.drag_started() {
                                state.dragged_module = Some(item.clone());
                            }
                        }
                    });
            }
        });
}
