#[cfg(windows)]
fn main() -> eframe::Result<()> {
    classmesh_teacher::ui_egui::run_teacher_ui()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-teacher-ui is available on Windows only");
}
