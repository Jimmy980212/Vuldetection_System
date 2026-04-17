public class InputSource {
    public static String fromArgs(String[] args) {
        return args.length > 0 ? args[0] : "guest";
    }
}
