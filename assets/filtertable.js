function filterServerTable() {
	const input = document.getElementById('serverInput');
	const filter = input.value.toUpperCase();
	const table = document.getElementById('server_table');
	const tr = table.getElementsByTagName('tr');
	for (let i = 1; i < tr.length; i++) {
		const td = tr[i].getElementsByTagName('td');
		let txtValue = '';
		for (let j = 0; j < td.length; j++) {
			txtValue += td[j].textContent || td[j].innerText;
		}
		if (txtValue.toUpperCase().indexOf(filter) > -1) {
			tr[i].style.display = '';
		} else {
			tr[i].style.display = 'none';
		}
	}
}

function filterNetworkTable() {
	const input = document.getElementById('networkInput');
	const filter = input.value.toUpperCase();
	const table = document.getElementById('network_table');
	const tr = table.getElementsByTagName('tr');
	for (let i = 1; i < tr.length; i++) {
		const td = tr[i].getElementsByTagName('td');
		let txtValue = '';
		for (let j = 0; j < td.length; j++) {
			txtValue += td[j].textContent || td[j].innerText;
		}
		if (txtValue.toUpperCase().indexOf(filter) > -1) {
			tr[i].style.display = '';
		} else {
			tr[i].style.display = 'none';
		}
	}
}