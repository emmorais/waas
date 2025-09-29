use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tracing_subscriber::fmt::format::FmtSpan;

/// Initialize Zama-styled logging with colorful output
pub fn init_zama_logging() {
    // Set up environment filter - defaults to info level
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Initialize tracing subscriber with Zama-style formatting
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_span_events(FmtSpan::CLOSE)
                .compact()
        )
        .init();
}
