use nu_ansi_term::Color;
use std::fmt;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing::{Event, Subscriber, Level};

/// Custom formatter that uses Zama.ai UI colors
pub struct ZamaFormatter;

impl<S, N> FormatEvent<S, N> for ZamaFormatter
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Get timestamp
        let timestamp = chrono::Utc::now().format("%H:%M:%S%.3f");
        
        // Color scheme matching the UI
        let (level_color, level_symbol) = match *event.metadata().level() {
            Level::ERROR => (Color::Rgb(239, 68, 68), "❌"), // #ef4444 - UI error red
            Level::WARN => (Color::Rgb(245, 158, 11), "⚠️"), // #f59e0b - UI warning yellow
            Level::INFO => (Color::Rgb(59, 130, 246), "ℹ️"), // #3b82f6 - UI primary blue
            Level::DEBUG => (Color::Rgb(34, 197, 94), "🔧"), // #22c55e - UI success green
            Level::TRACE => (Color::Rgb(168, 85, 247), "🔍"), // #a855f7 - UI info purple
        };
        
        // Background colors for better readability (matching UI glass morphism)
        let bg_color = Color::Rgb(15, 15, 23); // #0f0f17 - UI background
        let text_color = Color::Rgb(226, 232, 240); // #e2e8f0 - UI text
        let dim_color = Color::Rgb(148, 163, 184); // #94a3b8 - UI subtitle
        
        // Format: [TIME] LEVEL_SYMBOL TARGET - MESSAGE
        write!(
            writer,
            "{} {} {} {} {}",
            dim_color.paint(format!("[{}]", timestamp)),
            level_color.bold().paint(level_symbol),
            level_color.bold().paint(event.metadata().level().as_str()),
            dim_color.paint("→"),
            text_color.paint("")
        )?;

        // Format the message and fields
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        
        // Add file location if available (in dim color like UI)
        if let (Some(file), Some(line)) = (event.metadata().file(), event.metadata().line()) {
            write!(
                writer,
                " {}",
                dim_color.italic().paint(format!("({}:{})", file, line))
            )?;
        }

        writeln!(writer)?;
        Ok(())
    }
}

/// Initialize tracing with Zama.ai colors
pub fn init_zama_logging() {
    tracing_subscriber::fmt()
        .with_env_filter("waas=debug,info")
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true)
        .event_format(ZamaFormatter)
        .init();
}
