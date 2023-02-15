<?php
require_once dirname(__DIR__) . "/html/header.html";
require_once dirname(__DIR__) . "/html/search.html";
?>

<main>
    <div class="box blue">
        <div class="title-box">
            <h2 id="profile-name">Prenom Nom</h2>
            <img id="profile-picture" src="https://www.w3schools.com/howto/img_avatar.png" alt="Avatar">
        </div>
        <div class="profile-box">
            <div class="profile-title">
                Informations Personnelles
            </div>
            <div class="profile-info">
                <div>Email : <span>gerant@gmail.com</span></div>
            </div>
        </div>
        <div class="profile-box">
            <div class="profile-title">Affectation</div>
            <div class="profile-info">
                <div>Pole : <span>Info</span></div>
                <div>Grade : <span>Dictateur</span></div>
                <div>Tel : <span>+33 6 45 78 47 58 </span></div>
                <div>Adresse bureau : <span>10 rue du bureau</span></div>
            </div>
        </div>
        <div class="profile-box">
            <div class="profile-title">Informations avancées</div>
            <div class="profile-info">
                <div>test : <span>test</span></div>
                <div>test : <span>test</span></div>
            </div>
        </div>
    </div>
</main>

<?php
require_once dirname(__DIR__) . "/html/footer.html";
?>
