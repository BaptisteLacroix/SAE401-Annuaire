<?php
require dirname(__DIR__) . "/html/header.html";
?>


<main>
    <div class="containerLogin">
        <div class="loginImage">
            <img src="../../img/loginImage.jpg" alt="login">
        </div>

        <div class="login-box">
            <h2>Se connecter</h2>
            <form action="#" method="post">
                <div class="user-box">
                    <input type="text" name="E-mail" id="E-mail" required="" autocomplete="off">
                    <label>Identifiant</label>
                </div>
                <div class="user-box">
                    <input type="password" name="password" id="password" required="" autocomplete="off">
                    <label>Mot de passe</label>
                </div>


                <div class="remember">
                    <input type="checkbox" name="remember" id="remember">
                    <label for="remember"></label>
                    <label class="text" for="remember">Se souvenir de moi</label>
                </div>
                <div class="connection">
                    <input class="connect" type="submit" value="Se connecter">
                </div>
            </form>
        </div>
    </div>
</main>