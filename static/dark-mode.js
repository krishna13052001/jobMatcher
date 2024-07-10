const toggleButton = document.getElementById('theme-toggle');

toggleButton.addEventListener('click', () => {
    document.documentElement.classList.toggle('dark');
}); 