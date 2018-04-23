#include <platform/nabto_logging.h>
#include <stdio.h>

void nabto_default_log(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, va_list args) {
    printf("HERE\n");
}
struct nabto_logging nabto_log = { &nabto_default_log };

#ifdef HAS_NO_VARIADIC_MACROS
void fatal_adapter(uint32_t module, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_FATAL, "", 0, "", fmt, args);
    va_end(args);
}
void error_adapter(uint32_t module, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_ERROR, "", 0, "", fmt, args);
    va_end(args);
}
void warn_adapter(uint32_t module, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_WARN, "", 0, "", fmt, args);
    va_end(args);
}
void info_adapter(uint32_t module, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_INFO, "", 0, "", fmt, args);
    va_end(args);
}
void debug_adapter(uint32_t module, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_DEBUG, "", 0, "", fmt, args);
    va_end(args);
}
void trace_adapter(uint32_t module, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_TRACE, "", 0, "", fmt, args);
    va_end(args);
}
#else
void fatal_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_FATAL, module, line, file, fmt, args);
    va_end(args);
}
void error_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_ERROR, module, line, file, fmt, args);
    va_end(args);
}
void warn_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_WARN, module, line, file, fmt, args);
    va_end(args);
}
void info_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_INFO, module, line, file, fmt, args);
    va_end(args);
}
void debug_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_DEBUG, module, line, file, fmt, args);
    va_end(args);
}
void trace_adapter(uint32_t severity, uint32_t module, uint32_t line, const char* file, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    nabto_log.log(NABTO_LOG_SEVERITY_TRACE, module, line, file, fmt, args);
    va_end(args);
}
#endif
