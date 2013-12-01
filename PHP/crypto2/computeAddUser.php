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
if (!empty($_POST['ID']) AND !empty($_POST['Certificate'])) {
	try {
		$bdd = new PDO('mysql:host=localhost;dbname=crypto2', 'root', '', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
	} catch(Exception $e) {
		die('Error : ' . $e -> getMessage());
		echo 'Something went wrong...';
	}
} else {
	header('Location : add.php');
	exit();
}
$bdd -> exec("SET CHARACTER SET utf8");

$exists = $bdd -> query('Select * from Certificates where ID = ' . htmlspecialchars($_POST['ID']));
if ($exists -> fetch()) {
	$response = $bdd -> query('update Certificates set Certificate = "' . htmlspecialchars($_POST['Certificate']) . '" where ID = ' . htmlspecialchars($_POST['ID']));
}

else $response = $bdd -> query('Insert into Certificates (ID, Certificate) values(' . htmlspecialchars($_POST['ID']) . ', "' . htmlspecialchars($_POST['Certificate']) . '")');

redirection('index.php');

exit();
?>
