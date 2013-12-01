<?php
if (!isset($_SESSION))
	session_start();
?>

<?php
function redirection($url) {
	die('<meta http-equiv="refresh" content="0;URL=' . $url . '">');
}
?>

<?php
if (!empty($_POST['ID'])) {
	try {
		$bdd = new PDO('mysql:host=localhost;dbname=crypto2', 'root', '', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
	} catch(Exception $e) {
		die('Error : ' . $e -> getMessage());
		echo 'Something went wrong...';
	}
} else {
	header('Location : delete.php');
	exit();
}
$bdd -> exec("SET CHARACTER SET utf8");

$response = $bdd -> query('Delete from Certificates where ID = ' . htmlspecialchars($_POST['ID']));

redirection('index.php');

exit();
?>