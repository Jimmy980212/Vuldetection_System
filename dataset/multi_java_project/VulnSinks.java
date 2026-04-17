import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class VulnSinks {
    public static void sql(String uid) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement st = conn.createStatement();
        st.execute("CREATE TABLE users(id TEXT)");
        st.executeQuery("SELECT * FROM users WHERE id='" + uid + "'"); // CWE-89
        st.close();
        conn.close();
    }
}
