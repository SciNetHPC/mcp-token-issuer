// Minimal logging for the token-issuer: every line is prefixed with an
// ISO-8601 timestamp rendered in Eastern time (America/Toronto, DST-aware)
// with an explicit offset, so the instant stays unambiguous. Override the
// zone with LOG_TIME_ZONE (e.g. "UTC").
const LOG_TIME_ZONE = process.env.LOG_TIME_ZONE || "America/Toronto";

function timestamp(): string {
    if (LOG_TIME_ZONE === "UTC") {
        return new Date().toISOString();
    }
    const dtf = new Intl.DateTimeFormat("en-CA", {
        timeZone: LOG_TIME_ZONE,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        fractionalSecondDigits: 3,
        hourCycle: "h23",
    });
    const parts = dtf.formatToParts(new Date());
    const get = (type: string): string => {
        const part = parts.find((p) => p.type === type);
        return part ? part.value : "";
    };
    const y = get("year");
    const mo = get("month");
    const d = get("day");
    const h = get("hour");
    const mi = get("minute");
    const s = get("second");
    const f = get("fractionalSecond");
    const wallAsUtc = Date.UTC(
        Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), Number(f) || 0,
    );
    const offsetMin = Math.round((wallAsUtc - Date.now()) / 60000);
    const sign = offsetMin >= 0 ? "+" : "-";
    const abs = Math.abs(offsetMin);
    const offset = `${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
    return `${y}-${mo}-${d}T${h}:${mi}:${s}.${f}${offset}`;
}

function stringify(value: unknown): string {
    if (value instanceof Error) return value.stack || value.message;
    if (typeof value === "string") return value;
    if (typeof value === "object") {
        try {
            return JSON.stringify(value);
        } catch {
            return String(value);
        }
    }
    return String(value);
}

function write(level: "log" | "warn" | "error", args: unknown[]): void {
    const message = args.map(stringify).join(" ");
    const line = `${timestamp()} [${level.toUpperCase()}] ${message}`;
    if (level === "error") console.error(line);
    else if (level === "warn") console.warn(line);
    else console.log(line);
}

export const log = {
    log: (...args: unknown[]): void => write("log", args),
    warn: (...args: unknown[]): void => write("warn", args),
    error: (...args: unknown[]): void => write("error", args),
};
