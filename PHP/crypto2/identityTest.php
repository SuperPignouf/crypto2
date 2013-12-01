<?php session_start();

function redirection($url) {
	die('<meta http-equiv="refresh" content="0;URL=' . $url . '">');
}

if (isset($_POST['password']) && $_POST['password'] == "chicken") {

	$_SESSION['administrator'] = 1;

}

redirection("index.php");
exit();
?>		