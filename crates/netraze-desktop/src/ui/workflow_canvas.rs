use egui_snarl::ui::SnarlWidget;

use crate::state::AppState;
use crate::workflow::{WorkflowDocument, WorkflowViewer};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    // Session credentials take priority when an identity was rescanned with a
    // new secret; only Credential Manager entries are persisted on disk.
    let mut credentials = state.session_credentials.clone();
    credentials.extend(state.credentials.iter().cloned());
    let mut viewer = WorkflowViewer::new(credentials);
    let style = WorkflowDocument::snarl_style();
    let response = SnarlWidget::new()
        .id_salt("netraze_snarl_canvas")
        .style(style)
        .show(&mut state.workflow.snarl, &mut viewer, ui);

    // Node click → select in config panel; background click → deselect.
    if let Some(raw_id) = viewer.selected_node_id.take() {
        state.selected_workflow_node = Some(raw_id);
    } else if response.clicked() {
        state.selected_workflow_node = None;
    }

    // Collect login requests from the viewer into pending_logins
    for (ip, cred) in viewer.login_requests.drain(..) {
        state.pending_logins.push((ip, cred));
    }

    // Collect share enum requests — dispatched to runtime in app.rs
    for (host_node_id, host_ip, hostname, cred) in viewer.shares_requests.drain(..) {
        state
            .pending_share_enums
            .push((host_node_id.0, host_ip, hostname, cred));
    }

    // Collect user enum requests — dispatched to runtime in app.rs
    for (host_node_id, host_ip, hostname, cred) in viewer.users_requests.drain(..) {
        state.queue_user_enum(host_node_id.0, host_ip, hostname, cred);
    }

    // Collect dump requests — dispatched to runtime in app.rs
    for (host_node_id, host_ip, hostname, dump_type, cred) in viewer.dump_requests.drain(..) {
        state
            .pending_dumps
            .push((host_node_id.0, host_ip, hostname, dump_type, cred));
    }

    // Collect AV enum requests — dispatched to runtime in app.rs
    for (host_node_id, host_ip, hostname, cred) in viewer.enumav_requests.drain(..) {
        state
            .pending_enumav
            .push((host_node_id.0, host_ip, hostname, cred));
    }

    // Collect fingerprint requests
    for ip in viewer.fingerprint_requests.drain(..) {
        state.pending_fingerprints.push(ip);
    }

    // Collect console requests — open a console window for a pwned host
    for (host_ip, hostname, credential) in viewer.console_requests.drain(..) {
        state.open_console(host_ip, hostname, credential);
    }

    // Collect browse requests — create browser windows
    for (host_ip, share_name, cred) in viewer.browse_requests.drain(..) {
        use crate::ui::share_browser::ShareBrowserState;
        // Check if already open for this share
        let already_open = state
            .share_browsers
            .iter()
            .any(|b| b.open && b.host_ip == host_ip && b.share_name == share_name);
        if !already_open {
            let browser = ShareBrowserState::new(host_ip, share_name, cred);
            let browser_id = state.share_browsers.len();
            state.share_browsers.push(browser);
            state.pending_browse.push(browser_id);
        }
    }

    // Surface menu-handling errors (e.g. unresolvable credential label)
    for err in viewer.menu_errors.drain(..) {
        state.add_log(crate::runtime::LogLevel::Error, err);
    }

    // Drop: materialize dragged module node at cursor position on canvas.
    if let Some(module_name) = state.dragged_module.clone() {
        let released = ui.input(|i| i.pointer.any_released());
        let pointer_pos = ui.input(|i| i.pointer.interact_pos());

        if released {
            if let Some(pos) = pointer_pos {
                if response.rect.contains(pos) {
                    state.workflow.add_module_node(module_name, pos);
                }
            }
            state.dragged_module = None;
        }
    }
}
