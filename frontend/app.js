document.addEventListener("DOMContentLoaded", async () => {
    const statusMessage = document.getElementById("status-message");
    try {
        const response = await fetch("http://127.0.0.1:8000/ping");
        if (response.ok) {
            const data = await response.json();
            statusMessage.textContent = `Backend status: ${data.status}`;
            statusMessage.style.color = "#4ade80";
        } else {
            statusMessage.textContent = "Backend returned an error.";
            statusMessage.style.color = "#f87171";
        }
    } catch (error) {
        statusMessage.textContent = "Unable to connect to backend.";
        statusMessage.style.color = "#f87171";
    }
});
