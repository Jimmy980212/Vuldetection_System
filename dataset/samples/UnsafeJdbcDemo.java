import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class UnsafeJdbcDemo {
    public static void main(String[] args) throws Exception {
        String uid = args.length > 0 ? args[0] : "1";
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement st = conn.createStatement();
        st.execute("CREATE TABLE users(id TEXT, name TEXT)");
        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = '" + uid + "'"); // CWE-89
        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
        rs.close();
        st.close();
        conn.close();
    }
}
