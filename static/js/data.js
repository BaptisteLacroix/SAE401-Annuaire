let connection = document.getElementById("logoutText");

if (connection != null) {
    connection.addEventListener("click", logout);
}

function logout() {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "/logout");
    xhr.send();
}


