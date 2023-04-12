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
    setEvents();
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
                                }
                                // else if the last word in the id is value
                                else if (element.id.split("-").pop() === "value") {
                                    // replace the value element by the value
                                    element.value = value2;
                                } else if (element.id.split("-").pop() === "placeholder") {
                                    element.placeholder = value2;
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

function setEvents() {
    let filters = document.getElementsByClassName("filter");
    for (const element of filters) {
        element.addEventListener("click", function () {
            addOnSearchbar(element);
            element.classList.add("selected");
            element.setAttribute("name", "filter");
        });
    }
}

function addOnSearchbar(element) {
    let span = document.createElement("span");
    span.className = "active-filter";
    span.innerText = element.textContent;
    let searchBar = document.getElementById("filters-used");
    if (validate(element, searchBar)) {
        let croix = document.createElement("span");
        croix.className = "delete-element";
        croix.innerText = "❌";
        croix.addEventListener("click", function () {
            deleteElement(span);
            element.classList.remove("selected");
            element.removeAttribute("name");
        })
        span.appendChild(croix);
        searchBar.appendChild(span);
    }
}

function validate(element, container) {
    let activeFilters = container.getElementsByClassName("active-filter");
    if (activeFilters.length === 3) {
        return false;
    }
    for (let i = 0; i < activeFilters.length; i++) {
        if (activeFilters[i].textContent == element.textContent + "❌") {
            return false;
        }
    }
    return true;
}

function deleteElement(element) {
    let parent = element.parentElement;
    parent.removeChild(element);
}