<?php
$conn = new mysqli("mysql", "cmsuser", "cms123", "vulnu_cms");
$q = $_GET['q'] ?? '';
$sql = "SELECT * FROM students WHERE name LIKE '%$q%'";
$result = $conn->query($sql);
while($row = $result->fetch_assoc()) {
    echo $row['name'] . "<br>";
}
?>
<form>Search: <input name="q"><input type="submit"></form>