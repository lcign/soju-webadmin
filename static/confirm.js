// Destructive buttons carry data-confirm; nothing else on these pages needs JS.
document.addEventListener("click", function (ev) {
	var el = ev.target.closest("[data-confirm]");
	if (el && !window.confirm(el.getAttribute("data-confirm"))) {
		ev.preventDefault();
	}
});
