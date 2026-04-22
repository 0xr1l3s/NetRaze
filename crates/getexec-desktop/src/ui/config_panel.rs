use crate::runtime::RuntimeServices;
use crate::state::AppState;

const LABEL_COLOR: egui::Color32 = egui::Color32::from_rgb(160, 165, 175);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(102, 27, 28);

pub fn show(ui: &mut egui::Ui, state: &mut AppState, runtime: &RuntimeServices) {
    ui.label(
        egui::RichText::new("⚙ Configuration")
            .size(14.0)
            .strong()
            .color(egui::Color32::WHITE),
    );
    ui.add_space(8.0);

    // -- Target section --
    ui.label(egui::RichText::new("TARGET").small().strong().color(ACCENT));
    ui.add_space(2.0);

    ui.label(egui::RichText::new("IP / Range").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.target_config.target)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(4.0);

    ui.label(egui::RichText::new("Protocol").small().color(LABEL_COLOR));
    egui::ComboBox::from_id_salt("protocol_combo")
        .selected_text(&state.target_config.protocol)
        .width(ui.available_width())
        .show_ui(ui, |ui| {
            for proto in [
                "SMB", "LDAP", "RDP", "WinRM", "MSSQL", "SSH", "FTP", "Kerberos",
            ] {
                ui.selectable_value(
                    &mut state.target_config.protocol,
                    proto.to_owned(),
                    proto,
                );
            }
        });

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    // -- Credentials section --
    ui.label(
        egui::RichText::new("CREDENTIALS")
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    ui.label(egui::RichText::new("Username").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.username)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(2.0);

    ui.label(egui::RichText::new("Password").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.password)
            .desired_width(f32::INFINITY)
            .password(true),
    );
    ui.add_space(2.0);

    ui.label(egui::RichText::new("NTLM Hash").small().color(LABEL_COLOR));
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.ntlm_hash)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(2.0);

    ui.label(
        egui::RichText::new("Kerberos Ticket")
            .small()
            .color(LABEL_COLOR),
    );
    ui.add(
        egui::TextEdit::singleline(&mut state.credential_config.kerberos_ticket)
            .desired_width(f32::INFINITY)
            .font(egui::TextStyle::Monospace),
    );

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    // -- Execution section --
    ui.label(
        egui::RichText::new("EXECUTION")
            .small()
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Threads").small().color(LABEL_COLOR));
        ui.add(egui::DragValue::new(&mut state.threads).range(1..=1024));
    });
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Timeout (s)")
                .small()
                .color(LABEL_COLOR),
        );
        ui.add(egui::DragValue::new(&mut state.timeout_seconds).range(1..=600));
    });

    ui.add_space(4.0);
    if !state.selected_module.is_empty() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Module:").small().color(LABEL_COLOR));
            ui.label(
                egui::RichText::new(&state.selected_module)
                    .strong()
                    .color(ACCENT),
            );
        });
    }

    ui.add_space(12.0);

    // -- Run button --
    let run_text = if state.is_running {
        "⏳ Running..."
    } else {
        "▶ Run Workflow"
    };
    let run_color = if state.is_running {
        egui::Color32::from_rgb(40, 46, 58)
    } else {
        ACCENT
    };
    let run_button = egui::Button::new(
        egui::RichText::new(run_text)
            .strong()
            .color(egui::Color32::WHITE)
            .size(14.0),
    )
    .fill(run_color)
    .corner_radius(egui::CornerRadius::same(4));

    if ui
        .add_sized([ui.available_width(), 36.0], run_button)
        .clicked()
        && !state.is_running
    {
        state.is_running = true;
        state.status_text = "Running".to_owned();
        state.started_at = Some(std::time::Instant::now());
        state.progress = 0.0;
        state.progress_message = "Démarrage...".to_owned();

        // Build credential from config
        let credential = if !state.credential_config.username.is_empty() {
            Some(getexec_protocols::smb::SmbCredential::new(
                &state.credential_config.username,
                "", // domain extracted from username if needed
                &state.credential_config.password,
            ))
        } else {
            None
        };

        // Parse targets (single IP or comma-separated)
        let targets: Vec<String> = state
            .target_config
            .target
            .split(|c: char| c == ',' || c == ' ' || c == '\n')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        runtime.spawn_smb_scan(
            targets,
            credential,
            state.threads,
            state.timeout_seconds,
        );
    }

    // -- Selected host details --
    if let Some(selected) = state.selected_host.clone() {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new("SELECTED HOST")
                .small()
                .strong()
                .color(ACCENT),
        );
        ui.label(
            egui::RichText::new(&selected)
                .monospace()
                .color(egui::Color32::WHITE),
        );
    }
}
