<?php
/** KontrolVM By KuJoe (https://github.com/KuJoe/kontrolvm) **/

session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
	header("Location: index.php"); 
	exit; 
} else {
	if (isset($_GET['s'])) {
		if ($_GET['s'] == '1') {
			$success = "VM created successfully.";
		} elseif ($_GET['s'] == '2') {
			$success = "VM deleted successfully.";
		}
	}
	define('AmAllowed', TRUE);
	require_once('config.php');
	require_once('functions.php');
	$loggedin_id = $_SESSION['staff_id'];
	$chkActive = checkActive($loggedin_id);
	$chkLocked = checkLockedOut($loggedin_id);
	if($chkLocked == true OR $chkActive == false) {
		header("Location: logout.php");
		exit;
	}
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$token = $_POST["csrf_token"];
	if (validateCSRFToken($token)) {
		$memory = trim($_POST["memory"]);
		$memory = $memory * 1024;
		$disk_space1 = trim($_POST["disk_space1"]);
		$cpu_cores = trim($_POST["cpu_cores"]);
		$loc = $_POST["loc"];
		$result = createVM($memory,$disk_space1,$cpu_cores,$loc);
		if($result === true) {
			header("Location: vms.php?state=all&s=1");
		} else {
			$error = "VM create failed: ".$result;
		}
	} else {
		$error = "Invalid CSRF token.";
	}
}
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
$csrfToken = getCSRFToken();
if(isset($_GET['state']) AND $_GET['state'] == "all") {
	$servers = getVMList('all');
} else {
	$servers = getVMList('1');
}
$clusters = getClusters('1');
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
			<li><a href="nodes.php">Nodes</a></li>
			<li><a class="active" href="vms.php">VMs</a></li>
			<li><a href="users.php">Users</a></li>
			<li><a href="settings.php">Settings</a></li>
			<li style="font-weight: bold;"><a href="account.php"><?php echo htmlspecialchars($_SESSION["username"]); ?></a></li>
			<li><a href="logout.php"><i class="fa fa-sign-out" aria-hidden="true"></i></a></li>
		</ul>
	</nav>
	<div class="container" style="min-width:350px;max-width:1500px;">
		<p style="float:right;"><button id="addBtn" class="stylish-button"><i class="fa-solid fa-square-plus"></i> CREATE VM</button></p>
		<div id="addModal" class="modal">
			<div class="modal-content"">
				<span class="close">&times;</span>
				<h2>Create New VM</h2>
				<br />
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
					<input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
					<label for="memory">Memory (GB):</label>
					<input type="text" id="memory" name="memory" placeholder="4" required><br><br>
					<label for="cpu_cores">vCPU Cores:</label>
					<input type="text" id="cpu_cores" name="cpu_cores" placeholder="2" required><br><br>
					<label for="disk_space1">Disk Space (GB):</label>
					<input type="text" id="disk_space1" name="disk_space1" placeholder="50" required><br><br>
					<label for="loc">Cluster:</label>
					<select name="loc" style="text-align:center;">
					<?php foreach ($clusters as $cluster):?>
							<option value="<?php echo htmlspecialchars($cluster['loc']);?>">
					<?php echo htmlspecialchars($cluster['friendlyname']);?> 
						</option>
					<?php endforeach;?>
					</select><br /><br />
					<center><button type="submit" class="stylish-button"><i class="fa-solid fa-square-plus"></i> CREATE VM</button></center>
				</form>
			</div>
		</div>
		<h1>VMs</h1>
		<?php if (isset($success)) { ?>
			<div class="success-message"><?php echo $success; ?></div> 
		<?php } ?>
		<?php if (isset($error)) { ?>
			<div class="error-message"><?php echo $error; ?></div> 
		<?php } ?>
		<div class="table-container" style="max-width:1500px;">
		<input type="text" id="serverInput" oninput="filterServerTable()" placeholder="Search VMs">
		<table id="server_table">
			<thead>
				<tr>
					<th>Name</th>
					<th>Status</th>
					<th>Node</th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ($servers as $server):
					$vm_id = $server['vm_id'];
					$hostname = $server['hostname'];
					$node = getNodeDetails($server['node_id']);
				?>
				<tr>
				<td class="tname"><a href="vm.php?id=<?php echo $vm_id; ?>"><?php echo $hostname; ?></a></td>
				<td><span class="ticon" style="padding-right:4px;">Status: </span>
					<div id="server-status-<?php echo $vm_id;?>">
					<img src="assets/loading.gif" height='16' width='16' alt="Loading...">
					</div>
				</td>
				<td></span><a href="node.php?id=<?php echo $node['node_id']; ?>"><?php echo $node['hostname']; ?></a></td>
				</tr>
				<?php endforeach;?>
			</tbody>
		</table>
		</div>
		<p style="text-align:center;padding:10px;font-weight:bold;"><a href="vms.php?state=all">View All</a></p>
	</div>
	<?php include('footer.php'); ?>
	<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
	<script src="assets/filtertable.js"></script>
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
		// Get the modal
		var modal = document.getElementById("addModal");

		// Get the button that opens the modal
		var btn = document.getElementById("addBtn");

		// Get the <span> element that closes the modal
		var span = document.getElementsByClassName("close")[0];

		// When the user clicks the button, open the modal 
		btn.onclick = function() {
			modal.style.display = "block";
		}

		// When the user clicks on <span> (x), close the modal
		span.onclick = function() {
			modal.style.display = "none";
		}

		// When the user clicks anywhere outside of the modal, close it
		window.onclick = function(event) {
			if (event.target == modal) {
				modal.style.display = "none";
			}
		}

		function updateVmStatus(vm_id,vmname,nodeip,nodeport,nodeuser,nodepw) {
			const statusDiv = document.getElementById('server-status-' + vm_id);
			$.post("./get_vm_status.php", { 
				vmname: vmname, 
				nodeip: nodeip,
				nodeport: nodeport,
				nodeuser: nodeuser,
				nodepw: nodepw
			}, function(data) {
				if (data == "running") {
					statusDiv.innerHTML = "<img src='assets/online.png' height='16' width='16' alt='Running'>";
				} else {
					statusDiv.innerHTML = "<img src='assets/offline.png' height='16' width='16' alt='Stopped'>";
				}
			});
		}
		<?php foreach ($servers as $server):
			$node = getNodeDetails($server['node_id']);
		?>
			updateVmStatus('<?php echo $server['vm_id'];?>','<?php echo $server['name'];?>','<?php echo $node['ipaddr'];?>','<?php echo $node['sshport'];?>','<?php echo $node['sshuser'];?>','<?php echo $node['sshkey'];?>');
			setInterval(function() {
				updateVmStatus('<?php echo $server['vm_id'];?>','<?php echo $server['name'];?>','<?php echo $node['ipaddr'];?>','<?php echo $node['sshport'];?>','<?php echo $node['sshuser'];?>','<?php echo $node['sshkey'];?>');
			}, 15000);
		<?php endforeach;?>
	</script>
</body>
</html>