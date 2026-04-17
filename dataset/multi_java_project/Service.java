public class Service {
    public static void handle(String user) throws Exception {
        VulnSinks.sql(user);
    }
}
