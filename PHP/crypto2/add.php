<?php
if (!isset($_SESSION))
	session_start();
if (!isset($_SESSION['administrator'])) {
	header('Location: index.php');
	exit();
}
?>

<!DOCTYPE  html>

<html>
	<head>
		<?php
		include ("head.php");
		?>
	</head>

	<body>

		<header>
			<!--En-tête-->
			<h1>Add a user !</h1>
		</header>

		<section>
			<!--Zone centrale-->

			<form method = "post" action = "computeAddUser.php" >
				<p>
					<label for = "ID"> ID (matricule):</label>
					<input type = "text" name = "ID" id = "ID"/>
					<br/>
					<br/>

					<label for = "Certificate"> Add Certificate :</label><br/>
					<TEXTAREA name="Certificate" rows=19 cols=64>Your certificate</TEXTAREA>
					<br/>
					<br/>

					<input type = "submit" value = "Submit"/>
					<br/>
					<br/>

				</p>
		</section>

		<nav>
			<!--Menu-->
			<?php
				include ("menu.php");
			?>
		</nav>

		<footer>
			<!--Footer-->
			<?php
				include ("footer.php");
			?>
		</footer>

	</body>

</html>