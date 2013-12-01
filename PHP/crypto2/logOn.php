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
			<h1>Log In :</h1>
		</header>

		<section>
			<!--Zone centrale-->
			<form method = "post" action = "identityTest.php">

				<label for = "pass"> Your Password :</label>
				<input type = "password" name = "password" id = "pass"/>

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