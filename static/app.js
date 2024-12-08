// Function to fetch the user list from the backend
// async function fetchUserList() {
//     try {
//         const response = await fetch('/userlist');
//         if (!response.ok) {
//             throw new Error('Failed to fetch user list');
//         }
//         const userList = await response.json();
//         updateUserList(userList);
//     } catch (error) {
//         console.error("Error fetching user list:", error);
//     }
// }

function getUserlist() {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            updateList(JSON.parse(this.response.json));
        }
    }
    request.open("GET", "/userlist");
    request.send();
}

function updateList(){
    const tableBody = document.querySelector('#userListTable tbody');
    tableBody.innerHTML = ''; // Clear existing rows in the table

    userList.forEach(user => {
        const row = document.createElement('tr');

        const usernameCell = document.createElement('td');
        usernameCell.textContent = user.username;
        row.appendChild(usernameCell);

        const elapsedTimeCell = document.createElement('td');
        elapsedTimeCell.textContent = user.elapsedtime.toFixed(2); // Display time with 2 decimals
        row.appendChild(elapsedTimeCell);

        tableBody.appendChild(row);
    });
}
// Function to start polling the backend every second
function startPolling() {
    setInterval(getUserList, 1000); // Update every second
}

// Start polling on page load
window.onload = function() {
    alert("Welcome to our recipe app");
    startPolling(); // Start polling to update the user list every second
};