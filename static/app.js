function getUserList() {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            updateUserList(JSON.parse(this.response));
        }
    }
    request.open("GET", "/userlist");
    request.send();
}

function updateUserList(userList) {
    const tableBody = document.querySelector('#userListTable tbody');
    tableBody.innerHTML = ''; 

    userList.forEach(user => {
        const row = document.createElement('tr');

        const username = document.createElement('td');
        username.textContent = user.username;
        row.appendChild(username);

        const elapsedTime = document.createElement('td');
        elapsedTime.textContent = user.elapsedtime + " sec"; 
        row.appendChild(elapsedTime);

        tableBody.appendChild(row);
    });
}

window.onload = function() {
    alert("Welcome to our recipe app");
    setInterval(getUserList, 1000);  
};