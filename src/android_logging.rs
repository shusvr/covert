/// Called once when the JNI library is loaded. Host integration uses a no-op.
#[unsafe(no_mangle)]
pub extern "C" fn covert_android_init_logging() {
    #[cfg(target_os = "android")]
    android_logging::init();
}

#[cfg(target_os = "android")]
mod android_logging {
    use std::ffi::CString;
    use std::fmt::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Level, Metadata, Subscriber};

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(
            priority: i32,
            tag: *const std::ffi::c_char,
            text: *const std::ffi::c_char,
        ) -> i32;

    }
    unsafe extern "C" {
        fn __system_property_get(
            name: *const std::ffi::c_char,
            value: *mut std::ffi::c_char,
        ) -> i32;
    }
    fn minimum_priority() -> i32 {
        // PROP_VALUE_MAX is 92; property_get is available on our API 26 minimum.
        let mut value = [0u8; 92];
        unsafe {
            __system_property_get(c"log.tag.CovertSans".as_ptr(), value.as_mut_ptr().cast());
        }
        match value[0].to_ascii_uppercase() {
            b'V' | b'2' => 2,
            b'D' | b'3' => 3,
            b'I' | b'4' => 4,
            b'W' | b'5' => 5,
            b'E' | b'6' => 6,
            b'A' | b'7' => 7,
            b'S' | b'8' => 8,
            _ => 3,
        }
    }
    fn priority(level: &Level) -> i32 {
        match *level {
            Level::ERROR => 6,
            Level::WARN => 5,
            Level::INFO => 4,
            Level::DEBUG => 3,
            Level::TRACE => 2,
        }
    }
    struct AndroidLog;
    impl Subscriber for AndroidLog {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            matches!(metadata.target(), "covert::tunnel" | "covert::transport")
                && priority(metadata.level()) >= minimum_priority()
        }
        // Logcat properties can change without restarting or rebuilding the app.
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }
        fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
            Some(tracing::metadata::LevelFilter::TRACE)
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            Id::from_u64(NEXT.fetch_add(1, Ordering::Relaxed))
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if !self.enabled(event.metadata()) {
                return;
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            if let Ok(text) = CString::new(fields.0.replace('\0', "\\0")) {
                unsafe {
                    __android_log_write(
                        priority(event.metadata().level()),
                        c"CovertSans".as_ptr(),
                        text.as_ptr(),
                    );
                }
            }
        }
    }
    struct Fields(String);
    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                let _ = write!(self.0, "{value:?}");
            } else {
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
        }
    }
    pub fn init() {
        // Leave an existing host subscriber intact; never panic across JNI.
        let _ = tracing::subscriber::set_global_default(AndroidLog);
    }
}
