<?php
$conn = new mysqli("mysql", "cmsuser", "cms123", "vulnu_cms");
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);
    if ($result && $result->num_rows > 0) {
        echo "Login successful! FLAG{user_db_sqli}";
    } else {
        echo "Login failed";
    }
}
?>
<form method="post">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
<input type="submit">
</form>