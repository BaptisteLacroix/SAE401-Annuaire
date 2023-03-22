// On window load add eventlistener to the flags
window.addEventListener("load", function () {
    // Get the stored language or default to 'en'
    const storedLanguage = localStorage.getItem("language") || "en";
    setLanguage(storedLanguage);

    // Add eventlistener to the flags
    document.addEventListener("click", function (event) {
        if (event.target.id === "french") {
            setLanguage("fr");
        } else if (event.target.id === "english") {
            setLanguage("en");
        } else if (event.target.id === "spanish") {
            setLanguage("sp");
        }
    });
});

function setLanguage(language) {
    fetch(`../static/translations/${language}.json`)
        .then(response => response.json())
        .then(data => {
            // Store the selected language in local storage
            localStorage.setItem("language", language);
            // get the active page
            let page = document.querySelectorAll('[id^="page-"]')[0].id.split("-")[1];
            for (const [key, value] of Object.entries(data)) {
                const element = document.getElementById(key);
                if (element) {
                    element.innerHTML = value;
                }
                if (key === page) {
                    value.forEach((item) => {
                        for (const [key2, value2] of Object.entries(item)) {
                            const element = document.getElementById(key2);
                            if (element) {
                                // check if the element is a Node
                                if (element.id.indexOf("profile-") !== -1) {
                                    let spanText = element.innerHTML.split(">")[1].split("<")[0];
                                    element.innerHTML = value2 + `<span>` + spanText + `</span>`;
                                } else {
                                    element.innerHTML = value2;
                                }
                            }
                        }
                    });
                }
            }

        });
}
