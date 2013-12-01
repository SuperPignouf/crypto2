<?php if(!isset($_SESSION)) session_start(); ?>

<?php if (isset($_SESSION['administrator'])) { ?>
Search for :
<ul>
<li><a href = "delete.php" title = "delete">Delete</a></li>
<li><a href = "add.php" title = "add">Add</a></li>
</ul>
<?php } ?>

<?php if (!isset($_SESSION['administrator'])) { ?>
	
	<a href = "logOn.php" title = "Login">Log In</a>

<?php } if (isset($_SESSION['administrator'])) { ?>
	
	<a href = "logOff.php" title = "Clic here to disconnect !">Log Off</a>
<?php }

	