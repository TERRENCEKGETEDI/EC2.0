const date2 = new Date();
function live(){
    const date = new Date();
    const timeRemaining = new Date(date2.getTime() + 3600000 - date.getTime());
    document.getElementById("date").textContent = timeRemaining.toISOString().substr(11, 8);
}
setInterval(live, 1000);