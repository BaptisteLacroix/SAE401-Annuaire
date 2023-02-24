function generateFromSearch() {
    const container = document.getElementsByClassName("line");
    for (let i = 0; i < 20; i++) {
        let item = document.createElement("div");
        item.className = "item";

        item.addEventListener("click", function () {
            window.location.href = "profile";
        });


        let img = document.createElement("img");
        img.src = "../static/img/profile.png";
        img.alt = "test";
        img.className = "img";
        item.appendChild(img);

        let infos = document.createElement("div");
        infos.className = "infos";

        let statusInfo = document.createElement("div");
        statusInfo.className = "statusInfo";
        statusInfo.innerHTML = "TESTROLE"; // TODO: get role from server
        infos.appendChild(statusInfo);

        let nomInfo = document.createElement("div");
        nomInfo.className = "nomInfo";
        nomInfo.innerHTML = "NOM Prenom"; // TODO: get name from server
        infos.appendChild(nomInfo);

        item.appendChild(infos);
        container[0].appendChild(item);

    }
}

document.getElementById("logoutText").addEventListener("click", logout);

function logout() {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "/logout");
    xhr.send();
}