//! Vantage Desk — design system for egui/eframe.
//! Single call: `theme::apply(ctx)` once in `App::new`.
use egui::{Color32, CornerRadius, Stroke, Vec2};

// ── Surfaces ──────────────────────────────────────────────────────────────────
pub const CANVAS: Color32 = Color32::from_rgb(10, 10, 9); // #0A0A09
pub const BG: Color32 = Color32::from_rgb(18, 18, 17); // #121211
pub const PANEL: Color32 = Color32::from_rgb(23, 23, 22); // #171716
pub const ELEV_1: Color32 = Color32::from_rgb(30, 29, 27); // #1E1D1B
pub const ELEV_2: Color32 = Color32::from_rgb(38, 37, 35); // #262523
pub const CONSOLE_BG: Color32 = Color32::from_rgb(7, 7, 10); // #07070A

// ── Ink / borders ─────────────────────────────────────────────────────────────
pub const FG: Color32 = Color32::from_rgb(245, 244, 242); // #F5F4F2
pub const FG_2: Color32 = Color32::from_rgb(207, 204, 199); // #CFCCC7
pub const MUTED: Color32 = Color32::from_rgb(145, 140, 133); // #918C85
pub const MUTED_2: Color32 = Color32::from_rgb(106, 102, 96); // #6A6660
pub const LINE: Color32 = Color32::from_rgb(44, 43, 40); // #2C2B28
pub const LINE_2: Color32 = Color32::from_rgb(61, 59, 55); // #3D3B37

// ── Accent — one hue, five intensities ────────────────────────────────────────
pub const ACC_BG: Color32 = Color32::from_rgb(58, 31, 12); // #3A1F0C
pub const ACC_DIM: Color32 = Color32::from_rgb(138, 68, 19); // #8A4413
pub const ACC: Color32 = Color32::from_rgb(249, 125, 28); // #F97D1C
pub const ACC_HI: Color32 = Color32::from_rgb(255, 162, 90); // #FFA25A
pub const ACC_TEXT: Color32 = Color32::from_rgb(255, 199, 158); // #FFC79E

// ── Semantic — earned states only ─────────────────────────────────────────────
pub const SUCCESS: Color32 = Color32::from_rgb(85, 183, 127); // #55B77F
pub const SUCCESS_BG: Color32 = Color32::from_rgb(17, 36, 26); // #11241A
pub const WARNING: Color32 = Color32::from_rgb(226, 164, 76); // #E2A44C
pub const WARNING_BG: Color32 = Color32::from_rgb(42, 32, 17); // #2A2011
pub const ERROR: Color32 = Color32::from_rgb(232, 96, 76); // #E8604C
pub const ERROR_BG: Color32 = Color32::from_rgb(43, 20, 18); // #2B1412
pub const INFO: Color32 = Color32::from_rgb(95, 157, 232); // #5F9DE8
pub const INFO_BG: Color32 = Color32::from_rgb(17, 28, 43); // #111C2B

// ── Canvas dot grid ───────────────────────────────────────────────────────────
pub const DOT_COLOR: Color32 = Color32::from_rgb(30, 29, 27); // #1E1D1B on #0A0A09
pub const DOT_SPACING: f32 = 22.0;
pub const DOT_RADIUS: f32 = 0.9;

// ── Radii (pt) ────────────────────────────────────────────────────────────────
pub const R_BADGE: u8 = 3;
pub const R_BTN: u8 = 5;
pub const R_NODE: u8 = 8;
pub const R_MODAL: u8 = 12;

/// Apply the full Vantage design system. Call once in `App::new`.
pub fn apply(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();

    // Surfaces
    v.panel_fill = PANEL;
    v.window_fill = ELEV_1;
    v.extreme_bg_color = CONSOLE_BG;
    v.faint_bg_color = Color32::from_rgb(27, 26, 25); // #1B1A19 table stripe

    // Selection — orange accent
    v.selection.bg_fill = ACC_BG;
    v.selection.stroke = Stroke::new(1.0, ACC);

    // Hyperlink
    v.hyperlink_color = ACC_HI;

    // Window / popup chrome
    v.window_stroke = Stroke::new(1.0, LINE);
    v.window_shadow = egui::Shadow::NONE;
    v.popup_shadow = egui::Shadow::NONE;

    // noninteractive (labels, separators)
    v.widgets.noninteractive.bg_fill = ELEV_1;
    v.widgets.noninteractive.weak_bg_fill = ELEV_1;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, FG_2);
    v.widgets.noninteractive.bg_stroke = Stroke::new(0.5, LINE);
    v.widgets.noninteractive.corner_radius = CornerRadius::same(R_BTN);

    // inactive (buttons, inputs at rest)
    v.widgets.inactive.bg_fill = ELEV_2;
    v.widgets.inactive.weak_bg_fill = ELEV_2;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, FG);
    v.widgets.inactive.bg_stroke = Stroke::new(0.5, LINE);
    v.widgets.inactive.corner_radius = CornerRadius::same(R_BTN);

    // hovered
    v.widgets.hovered.bg_fill = Color32::from_rgb(47, 45, 42); // #2F2D2A
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(47, 45, 42);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, FG);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, LINE_2);
    v.widgets.hovered.corner_radius = CornerRadius::same(R_BTN);

    // active (pressed)
    v.widgets.active.bg_fill = ACC_BG;
    v.widgets.active.weak_bg_fill = ACC_BG;
    v.widgets.active.fg_stroke = Stroke::new(1.0, ACC_TEXT);
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACC_DIM);
    v.widgets.active.corner_radius = CornerRadius::same(R_BTN);

    // open (dropdown expanded)
    v.widgets.open.bg_fill = ACC_BG;
    v.widgets.open.weak_bg_fill = ACC_BG;
    v.widgets.open.fg_stroke = Stroke::new(1.0, ACC);
    v.widgets.open.bg_stroke = Stroke::new(1.0, ACC_DIM);
    v.widgets.open.corner_radius = CornerRadius::same(R_BTN);

    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(6.0, 4.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    style.spacing.interact_size.y = 24.0;
    style.spacing.indent = 16.0;
    ctx.set_style(style);
}
