<%@ page import="java.sql.*" %>
<%
String id = request.getParameter("id");
try {
    Class.forName("oracle.jdbc.OracleDriver");
    Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@oracle:1521/XE", "system", "manager");
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM research_papers WHERE id=" + id);
    while(rs.next()) {
        out.println(rs.getString("title"));
    }
    conn.close();
} catch(Exception e) {
    out.println("Error: " + e.getMessage());
}
%>