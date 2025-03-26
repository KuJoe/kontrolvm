// JavaScript code to handle theme switching (from previous responses)
const themeToggle = document.getElementById('theme-toggle');
const body = document.body;

// Load the user's preferred theme from localStorage
const savedTheme = localStorage.getItem('theme');
if(savedTheme === 'dark') {
	body.classList.add('dark-mode');
	themeToggle.checked = true; 
}

themeToggle.addEventListener('change', () => {
	if(themeToggle.checked) {
		body.classList.add('dark-mode');
		localStorage.setItem('theme', 'dark');
	} else {
		body.classList.remove('dark-mode');
		localStorage.setItem('theme', 'light');
	}
});