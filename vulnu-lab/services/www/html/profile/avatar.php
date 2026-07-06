<?php
if ($_FILES['avatar']) {
    $target = "uploads/" . basename($_FILES["avatar"]["name"]);
    move_uploaded_file($_FILES["avatar"]["tmp_name"], $target);
    echo "Uploaded to $target";
}
?>
<form method="post" enctype="multipart/form-data">
<input type="file" name="avatar">
<input type="submit">
</form>