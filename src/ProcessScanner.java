import java.io.PrintWriter;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ProcessScanner {
    private static final Pattern ENCODED_COMMAND =
            Pattern.compile("(?:^|\\s)-(?:enc|encodedcommand)(?:\\s|:|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HIDDEN_WINDOW =
            Pattern.compile("(?:^|\\s)-(?:windowstyle\\s+hidden|w\\s+hidden)(?:\\s|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXECUTION_POLICY_BYPASS =
            Pattern.compile("(?:^|\\s)-executionpolicy\\s+bypass(?:\\s|$)", Pattern.CASE_INSENSITIVE);

    public static void main(String[] args) {
        // Cache names from one snapshot so parent PIDs can be shown with readable context.
        List<ProcessHandle> processes = ProcessHandle.allProcesses().collect(Collectors.toList());
        Map<Long, String> processNames = new HashMap<>();
        for (ProcessHandle process : processes) {
            processNames.put(process.pid(), processName(process.info().command().orElse(""), process.pid()));
        }

        long scannerPid = ProcessHandle.current().pid();
        String timestamp = OffsetDateTime.now().toString();
        try (PrintWriter out = new PrintWriter(System.out, true)) {
            out.println("[");
            boolean first = true;
            for (ProcessHandle process : processes) {
                // Exclude this scanner so it does not appear as a new process on every scan.
                if (process.pid() == scannerPid) {
                    continue;
                }

                ProcessHandle.Info info = process.info();
                String executablePath = info.command().orElse(null);
                String name = processNames.get(process.pid());
                Long parentPid = process.parent().map(ProcessHandle::pid).orElse(null);
                String parentName = parentPid == null ? null : processNames.get(parentPid);
                // Emit selected PowerShell indicators only; never include the raw command line.
                List<String> commandLineIndicators =
                        commandLineIndicators(name, info.commandLine().orElse(""));

                if (!first) {
                    out.println(",");
                }
                out.print("{\"pid\":" + process.pid()
                        + ",\"process_name\":\"" + escapeJson(name) + "\""
                        + ",\"executable_path\":" + jsonString(executablePath)
                        + ",\"parent_pid\":" + (parentPid == null ? "null" : parentPid)
                        + ",\"parent_process_name\":" + jsonString(parentName)
                        + ",\"started_at\":" + jsonString(info.startInstant().map(Object::toString).orElse(null))
                        + ",\"command_line_indicators\":" + jsonArray(commandLineIndicators)
                        + ",\"timestamp\":\"" + escapeJson(timestamp) + "\"}");
                first = false;
            }
            out.println();
            out.println("]");
            if (out.checkError()) {
                System.err.println("Could not write process scan output.");
                System.exit(1);
            }
        }
    }

    private static String processName(String command, long pid) {
        if (command != null && !command.isBlank()) {
            String normalized = command.replace('\\', '/');
            int separator = normalized.lastIndexOf('/');
            return separator >= 0 ? normalized.substring(separator + 1) : normalized;
        }
        return "PID " + pid;
    }

    private static List<String> commandLineIndicators(String processName, String commandLine) {
        List<String> indicators = new ArrayList<>();
        String name = processName.toLowerCase(Locale.ROOT);
        if (!name.equals("powershell.exe") && !name.equals("pwsh.exe")
                && !name.equals("powershell") && !name.equals("pwsh")) {
            return indicators;
        }
        if (ENCODED_COMMAND.matcher(commandLine).find()) {
            indicators.add("encoded_powershell_command");
        }
        if (HIDDEN_WINDOW.matcher(commandLine).find()) {
            indicators.add("hidden_powershell_window");
        }
        if (EXECUTION_POLICY_BYPASS.matcher(commandLine).find()) {
            indicators.add("powershell_execution_policy_bypass");
        }
        return indicators;
    }

    private static String jsonString(String value) {
        return value == null ? "null" : "\"" + escapeJson(value) + "\"";
    }

    private static String jsonArray(List<String> values) {
        return values.stream()
                .map(value -> "\"" + escapeJson(value) + "\"")
                .collect(Collectors.joining(",", "[", "]"));
    }

    private static String escapeJson(String value) {
        // Escape metadata so quotes and control characters cannot break the JSON output.
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '"': escaped.append("\\\""); break;
                case '\\': escaped.append("\\\\"); break;
                case '\b': escaped.append("\\b"); break;
                case '\f': escaped.append("\\f"); break;
                case '\n': escaped.append("\\n"); break;
                case '\r': escaped.append("\\r"); break;
                case '\t': escaped.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.toString();
    }
}
