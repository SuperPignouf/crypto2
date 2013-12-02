<?php
if (!isset($_SESSION))
	session_start();
?>

<?php
function redirection($url) {
	die('<meta http-equiv="refresh" content="0;URL=' . $url . '">');
}
?>

<?

if (!empty($_POST['ID'])) {
	
	try {
		$bdd = new PDO('mysql:host=localhost;dbname=crypto2', 'root', '', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
	} catch(Exception $e) {
		echo "Connection à MySQL impossible : ", $e->getMessage();
		die();
	}
} else {
	redirection('delete.php');
	exit();
}
$bdd -> exec("SET CHARACTER SET utf8");

$response = $bdd -> query('Delete from certificates where ID = ' . htmlspecialchars($_POST['ID']));

redirection('index.php');

exit();
?>
