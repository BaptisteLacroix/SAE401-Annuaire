document.getElementById("logoutText").addEventListener("click", logout);

function logout() {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "/logout");
    xhr.send();
}