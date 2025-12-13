//! Progress reporting utilities for signing operations.
//! Progress reporting infrastructure with terminal display coordination.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Progress indicator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStyle {
    /// Simple percentage display
    Percentage,
    /// Progress bar with percentage
    ProgressBar,
    /// Spinning indicator
    Spinner,
    /// Silent mode (no visual indicator)
    Silent,
}

/// Progress reporter trait for different operation types
pub trait ProgressReporter: Send + Sync {
    /// Update progress with current position and total
    fn update(&self, current: u64, total: u64);

    /// Set the current status message
    fn set_message(&self, message: &str);

    /// Mark the operation as completed
    fn finish(&self);

    /// Mark the operation as failed with error message
    fn finish_with_error(&self, error: &str);
}

/// Terminal-based progress indicator
pub struct TerminalProgress {
    style: ProgressStyle,
    start_time: Instant,
    last_update: Arc<Mutex<Instant>>,
    current_message: Arc<Mutex<String>>,
    is_finished: Arc<Mutex<bool>>,
    bar_width: usize,
}

impl TerminalProgress {
    /// Create a new terminal progress indicator
    #[must_use]
    pub fn new(style: ProgressStyle) -> Self {
        Self {
            style,
            start_time: Instant::now(),
            last_update: Arc::new(Mutex::new(Instant::now())),
            current_message: Arc::new(Mutex::new(String::new())),
            is_finished: Arc::new(Mutex::new(false)),
            bar_width: 40,
        }
    }

    /// Create progress indicator with custom bar width
    #[must_use]
    pub fn with_bar_width(style: ProgressStyle, width: usize) -> Self {
        let mut progress = Self::new(style);
        progress.bar_width = width;
        progress
    }

    /// Render the progress display
    fn render(&self, current: u64, total: u64, message: &str) {
        if *self.is_finished.lock().unwrap() {
            return;
        }

        // Throttle updates to avoid too frequent redraws
        {
            let mut last_update = self.last_update.lock().unwrap();
            let now = Instant::now();
            if now.duration_since(*last_update) < Duration::from_millis(100) {
                return; // Skip this update
            }
            *last_update = now;
        }

        match self.style {
            ProgressStyle::Percentage => self.render_percentage(current, total, message),
            ProgressStyle::ProgressBar => self.render_progress_bar(current, total, message),
            ProgressStyle::Spinner => self.render_spinner(message),
            ProgressStyle::Silent => {} // No output
        }
    }

    /// Render percentage display
    fn render_percentage(&self, current: u64, total: u64, message: &str) {
        let percentage = if total > 0 {
            (current as f64 / total as f64 * 100.0) as u8
        } else {
            0
        };

        let elapsed = self.start_time.elapsed();
        print!(
            "\r🔄 {} - {}% ({}/{}) - {:.1}s",
            message,
            percentage,
            current,
            total,
            elapsed.as_secs_f64()
        );
        io::stdout().flush().unwrap();
    }

    /// Render progress bar
    fn render_progress_bar(&self, current: u64, total: u64, message: &str) {
        let percentage = if total > 0 {
            current as f64 / total as f64
        } else {
            0.0
        };

        let filled = (self.bar_width as f64 * percentage) as usize;
        let empty = self.bar_width - filled;

        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));

        let elapsed = self.start_time.elapsed();
        let eta = if current > 0 && percentage > 0.0 {
            let total_estimated = elapsed.as_secs_f64() / percentage;
            let remaining = total_estimated - elapsed.as_secs_f64();
            if remaining > 0.0 {
                format!(" ETA: {remaining:.1}s")
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        print!(
            "\r🔄 {} [{}] {:.1}%{}",
            message,
            bar,
            percentage * 100.0,
            eta
        );
        io::stdout().flush().unwrap();
    }

    /// Render spinner
    fn render_spinner(&self, message: &str) {
        let spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let elapsed_millis = self.start_time.elapsed().as_millis();
        let spinner_index = (elapsed_millis / 100) % spinner_chars.len() as u128;
        let spinner = spinner_chars[spinner_index as usize];

        let elapsed = self.start_time.elapsed();
        print!("\r{} {} - {:.1}s", spinner, message, elapsed.as_secs_f64());
        io::stdout().flush().unwrap();
    }

    /// Clear the current line
    fn clear_line(&self) {
        print!("\r{}\r", " ".repeat(80));
        io::stdout().flush().unwrap();
    }
}

impl ProgressReporter for TerminalProgress {
    fn update(&self, current: u64, total: u64) {
        let message = self.current_message.lock().unwrap().clone();
        self.render(current, total, &message);
    }

    fn set_message(&self, message: &str) {
        *self.current_message.lock().unwrap() = message.to_string();
    }

    fn finish(&self) {
        *self.is_finished.lock().unwrap() = true;
        self.clear_line();

        let elapsed = self.start_time.elapsed();
        let message = self.current_message.lock().unwrap().clone();
        println!(
            "[+] {} - Completed in {:.1}s",
            message,
            elapsed.as_secs_f64()
        );
    }

    fn finish_with_error(&self, error: &str) {
        *self.is_finished.lock().unwrap() = true;
        self.clear_line();

        let elapsed = self.start_time.elapsed();
        let message = self.current_message.lock().unwrap().clone();
        println!(
            "[!] {} - Failed after {:.1}s: {}",
            message,
            elapsed.as_secs_f64(),
            error
        );
    }
}

/// File operation progress tracker
pub struct FileProgress {
    reporter: Arc<dyn ProgressReporter>,
    total_bytes: u64,
    processed_bytes: u64,
}

impl FileProgress {
    /// Create a new file progress tracker
    pub fn new(reporter: Arc<dyn ProgressReporter>, total_bytes: u64) -> Self {
        Self {
            reporter,
            total_bytes,
            processed_bytes: 0,
        }
    }

    /// Update progress with bytes processed
    pub fn update(&mut self, bytes_processed: u64) {
        self.processed_bytes = bytes_processed.min(self.total_bytes);
        self.reporter.update(self.processed_bytes, self.total_bytes);
    }

    /// Add to the processed bytes count
    pub fn add_processed(&mut self, additional_bytes: u64) {
        self.processed_bytes = (self.processed_bytes + additional_bytes).min(self.total_bytes);
        self.reporter.update(self.processed_bytes, self.total_bytes);
    }

    /// Set the current operation message
    pub fn set_message(&self, message: &str) {
        self.reporter.set_message(message);
    }

    /// Mark the operation as completed
    pub fn finish(&self) {
        self.reporter.finish();
    }

    /// Mark the operation as failed
    pub fn finish_with_error(&self, error: &str) {
        self.reporter.finish_with_error(error);
    }

    /// Get the current progress percentage
    #[must_use]
    pub fn percentage(&self) -> f64 {
        if self.total_bytes > 0 {
            self.processed_bytes as f64 / self.total_bytes as f64 * 100.0
        } else {
            0.0
        }
    }
}

/// Null progress reporter for silent operations
pub struct NullProgress;

impl ProgressReporter for NullProgress {
    fn update(&self, _current: u64, _total: u64) {}
    fn set_message(&self, _message: &str) {}
    fn finish(&self) {}
    fn finish_with_error(&self, _error: &str) {}
}

/// Progress factory for creating appropriate progress indicators
pub struct ProgressFactory;

impl ProgressFactory {
    /// Create a progress reporter based on environment and preferences
    #[must_use]
    pub fn create_reporter(style: ProgressStyle) -> Arc<dyn ProgressReporter> {
        // Check if we're in a terminal
        if atty::is(atty::Stream::Stdout) {
            Arc::new(TerminalProgress::new(style))
        } else {
            // Not in a terminal, use silent mode
            Arc::new(NullProgress)
        }
    }

    /// Create a file progress tracker with automatic reporter selection
    #[must_use]
    pub fn create_file_progress(total_bytes: u64, style: ProgressStyle) -> FileProgress {
        let reporter = Self::create_reporter(style);
        FileProgress::new(reporter, total_bytes)
    }

    /// Determine appropriate progress style based on operation type and file size
    #[must_use]
    pub fn suggest_style(operation_type: &str, file_size: u64) -> ProgressStyle {
        match operation_type {
            "signing" | "verification" => {
                if file_size > 10 * 1024 * 1024 {
                    // > 10MB
                    ProgressStyle::ProgressBar
                } else if file_size > 1024 * 1024 {
                    // > 1MB
                    ProgressStyle::Percentage
                } else {
                    ProgressStyle::Spinner
                }
            }
            "network" => ProgressStyle::Spinner,
            _ => ProgressStyle::Percentage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_file_progress_creation() {
        let reporter = Arc::new(NullProgress);
        let mut progress = FileProgress::new(reporter, 1000);

        assert_eq!(progress.percentage(), 0.0);

        progress.update(500);
        assert_eq!(progress.percentage(), 50.0);

        progress.update(1000);
        assert_eq!(progress.percentage(), 100.0);
    }

    #[test]
    fn test_progress_factory_style_suggestion() {
        assert_eq!(
            ProgressFactory::suggest_style("signing", 100 * 1024 * 1024),
            ProgressStyle::ProgressBar
        );

        assert_eq!(
            ProgressFactory::suggest_style("signing", 5 * 1024 * 1024),
            ProgressStyle::Percentage
        );

        assert_eq!(
            ProgressFactory::suggest_style("signing", 100 * 1024),
            ProgressStyle::Spinner
        );

        assert_eq!(
            ProgressFactory::suggest_style("network", 1000),
            ProgressStyle::Spinner
        );
    }

    #[test]
    fn test_terminal_progress_creation() {
        let progress = TerminalProgress::new(ProgressStyle::ProgressBar);
        assert_eq!(progress.bar_width, 40);

        let progress_custom = TerminalProgress::with_bar_width(ProgressStyle::ProgressBar, 60);
        assert_eq!(progress_custom.bar_width, 60);
    }
}
