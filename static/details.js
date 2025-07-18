document.addEventListener('DOMContentLoaded', function () {
    let attempts = 0;
    const maxAttempts = 3;

    const interval = setInterval(() => {
        if (attempts >= maxAttempts) {
            clearInterval(interval);  // Stop trying after 3 attempts
            console.warn("Max retries reached. Stopping attempts.");
            return;
        }

        fetch('/api/user_data')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error(data.error);
                    attempts++;
                } else {
                    // Reset attempts on success if needed
                    console.log("Data fetched successfully");

                    document.getElementById("name").innerHTML = data.firstname + " (Student)";
                    document.getElementById("surname").innerHTML = data.surname;
                    document.getElementById("initials").innerHTML = data.firstname;
                    document.getElementById("student-number").innerHTML = "123456789";
                    document.getElementById("email").innerHTML = data.email;
                    document.getElementById("contact-number").innerHTML = data.phone;

                    // Save to localStorage (optional)
                    localStorage.setItem("Name", data.firstname);
                    localStorage.setItem("District", data.surname);
                    localStorage.setItem("Email", data.email);
                    localStorage.setItem("Phone", data.phone);

                    clearInterval(interval);  // ✅ Success! Stop interval
                }
            })
            .catch(error => {
                console.error('Error fetching user data:', error);
                attempts++;
            });

    }, 1000);  // Run every second, max 3 tries
});
