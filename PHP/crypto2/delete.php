<?php if(!isset($_SESSION)) session_start();
	if (!isset($_SESSION['administrator'])){
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
			<h1>Search user :</h1>
		</header>

		<section>
			<!--Zone centrale-->
			<form method = "post" action = "computeDelete.php">

				<label for = "ID"> ID of the user to delete :</label>
				<input type = "text" name = "ID" id = "ID"/>

				<input type = "submit" value = "Submit"/>

			</form>
		</section>

		<footer>
			<!--Footer-->
			<?php
			include ("footer.php");
			?>
		</footer>

	</body>

</html>