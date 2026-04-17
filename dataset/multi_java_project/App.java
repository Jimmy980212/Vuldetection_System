public class App {
    public static void main(String[] args) throws Exception {
        String user = InputSource.fromArgs(args);
        Service.handle(user);
    }
}
