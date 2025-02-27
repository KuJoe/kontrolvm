<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	define('AmAllowed', TRUE);
	require_once('config.php');
	require_once('functions.php');
	$loggedin_id = (int)$_SESSION['staff_id'];
	$myrole = (int)$_SESSION["staff_role"];
	$chkActive = checkActive($loggedin_id);
	$chkLocked = checkLockedOut($loggedin_id);
	if($chkLocked == true OR $chkActive == false) {
		header("Location: logout.php");
		exit;
	}
}
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
$csrfToken = getCSRFToken();
$totalLogs = getLogsTotal();
$page = isset($_GET['p']) && is_numeric($_GET['p']) ? $_GET['p'] : 1;
$perPage = 20;
$offset = ($page - 1) * $perPage;
$totalPages = ceil($totalLogs / $perPage);
$logs = getLogs($perPage,$offset);

?>
<!DOCTYPE html>
<html lang="en">
<?php include('header.php'); ?>
<body>
	<nav>
		<input type="checkbox" id="check">
		<label for="check" class="checkbtn">
			<i class="fas fa-bars"></i>
		</label>
		<label class="logo"><a href="index.php"><img src="assets/logo.png" alt="KontrolVM Logo"></a></label>
		<ul>
			<li><a href="index.php">Dashboard</a></li>
			<?php if (in_array($myrole, ['2', '9'])) { ?> <li><a href="clusters.php">Infrastructure</a></li> <?php } ?>
			<?php if (in_array($myrole, ['1', '9'])) { ?> <li><a href="users.php">Users</a></li> <?php } ?>
			<li><a class="active" href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<ul class="submenu">
		<li><a href="settings.php">General</a></li>
		<li><a href="isos.php">ISOs</a></li>
		<li><a href="ipv4.php">IPv4 Addresses</a></li>
		<li><a href="ipv6.php">IPv6 Addresses</a></li>
		<li><a class="active" href="logs.php">Logs</a></li>
	</ul>
	<div class="container">
		<h1>Logs</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
			<table id="server_table">
				<thead>
					<tr>
						<th>Message</th>
						<th>Timestamp</th>
					</tr>
				</thead>
				<tbody>
				<?php if (count($logs) > 0) {
					foreach ($logs as $log) {
						echo '<tr>';
						echo "<td class='tname'>" . htmlspecialchars($log['log_message']) . "</td>";
						echo "<td>" . htmlspecialchars($log['created_at']) . "</td>";
						echo '</tr>';
					}
				} else {
					echo '<tr><td colspan="2">No log entries</td></tr>';
				}?>
				</tbody>
			</table>
			<div class="pagination">
				<?php if ($page > 5): ?>
					<a href="?p=<?php echo $page - 1; ?>">&laquo; Previous</a>
				<?php endif; ?>

				<?php
					$maxPagesToShow = 5;
					$startPage = max(1, $page - floor($maxPagesToShow / 2));
					$endPage = min($totalPages, $startPage + $maxPagesToShow - 1);

					if ($page > floor($maxPagesToShow/2) && $totalPages > $maxPagesToShow) {
						echo "<a href='?p=1'>1</a> ... ";
					}

					for ($i = $startPage; $i <= $endPage; $i++): ?>
						<a href="?p=<?php echo $i; ?>" <?php if ($i == $page) echo 'class="active"'; ?>><?php echo $i; ?></a>
					<?php endfor;

					if ($endPage < $totalPages) {
						echo "... <a href='?p=$totalPages'>$totalPages</a>";
					}
				?>

				<?php if ($page < $totalPages): ?>
					<a href="?p=<?php echo $page + 1; ?>">Next &raquo;</a>
				<?php endif; ?>
			</div>
		</div>
	</div>
	<?php include('footer.php'); ?>
	<script>
		// JavaScript code to handle theme switching (from previous responses)
		const themeToggle = document.getElementById('theme-toggle');
		const body = document.body;

		// Load the user's preferred theme from localStorage
		const savedTheme = localStorage.getItem('theme');
		if (savedTheme === 'dark') {
			body.classList.add('dark-mode');
			themeToggle.checked = true; 
		}

		themeToggle.addEventListener('change', () => {
			if (themeToggle.checked) {
				body.classList.add('dark-mode');
				localStorage.setItem('theme', 'dark');
			} else {
				body.classList.remove('dark-mode');
				localStorage.setItem('theme', 'light');
			}
		});
	</script>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="assets/filtertable.js"></script>
</body>
</html>