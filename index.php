<?php
    require "header.html";
    require "search.html";
    //require __DIR__."annexe/search.php";
?>

<main>
    <section id="prompt">
        <p>
            La recherche s'effectue sur le début du nom de la personne suivie de son prénom :
        </p>
        <p>
            "Mar" recherche toutes les personnes dont le nom commence par mar
        </p>
        <p>
            "Martin m" recherche toutes les personnes nommées martin dont le prénom commence par m
        </p>
        <p>
            Il est possible d'utiliser le caractère * comme joker :
        </p>
        <p>
            "Mar* m" recherche toutes les personnes dont le nom commence par mar et dont le prénom commence par m
        </p>
        <p>
            Pour les noms composés, le séparateur entre la particule et le nom n'est pas normalisé, il se peut que
            ce soit un tiret, un blanc, un souligné. Utilisez le joker * pour couvrir tous les cas :
        </p>
        <p>
            le*corbusier couvre lecorbusier, le corbusier, le-corbusier et le_corbusier
        </p>
        <p>
            si votre recherche est toujours infructueuse, recherchez sur une partie du nom, par exemple : *corbus
        </p>
    </section>
    
</main>

<?php
require "footer.html";
?>

</body>
</html>