<?php
require_once dirname(__DIR__) . "/html/header.html";
require_once dirname(__DIR__) . "/html/search.html";
//require __DIR__ . "annexe/search.php";
?>

<script>
   window.addEventListener('load', function() {
      generateFromSearch();
   });
</script>

<main>
   <div class="line">
   </div>
</main>

<?php
require_once dirname(__DIR__) . "/html/footer.html";
?>

</body>

</html>