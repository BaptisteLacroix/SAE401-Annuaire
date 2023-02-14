function generateFromSearch() {
   const container = document.getElementsByClassName("line");
   for (let i = 0; i < 20; i++) {
      let item = document.createElement("div");
      item.className = "item";

      item.addEventListener("click", function () {
         window.location.href = "./profile.html";
      });


      let img = document.createElement("img");
      img.src = "./img/profile.png";
      img.alt = "test";
      img.className = "img";
      item.appendChild(img);

      let infos = document.createElement("div");
      infos.className = "infos";

      let statusInfo = document.createElement("div");
      statusInfo.className = "statusInfo";
      statusInfo.innerHTML = "TESTROLE";
      infos.appendChild(statusInfo);

      let nomInfo = document.createElement("div");
      nomInfo.className = "nomInfo";
      nomInfo.innerHTML = "NOM Prenom";
      infos.appendChild(nomInfo);

      item.appendChild(infos);
      container[0].appendChild(item);

   }
}
