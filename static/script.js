// Animate ML confidence bars on load
document.addEventListener("DOMContentLoaded", function() {
    const bars = document.querySelectorAll(".progress-bar");
    bars.forEach(bar => {
        const width = bar.getAttribute("aria-valuenow");
        bar.style.width = "0%"; // start from 0
        setTimeout(() => {
            bar.style.width = width + "%"; // animate to actual value
        }, 100); // slight delay for effect
    });
});
