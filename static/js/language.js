// On window load add eventlistener to the flags
window.addEventListener("load", function () {
    // Get the stored language or default to 'en'
    //    const storedLanguage = localStorage.getItem("language") || "en";
    //    setLanguage(storedLanguage);

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

    const select = document.querySelector('.multiple-selection');

    select.addEventListener('mousedown', function (e) {
        const option = e.target;
        if (option.tagName === 'OPTION') {
            option.classList.toggle('selected');
            e.preventDefault(); // prevent the default blue selection
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

function setEvents() {
    let filters = document.getElementsByClassName("filter");
    for (let i = 0; i < filters.length; i++) {
        filters[i].addEventListener("click", function () {
            addOnSearchbar(filters[i]);
            filters[i].classList.add("selected");
            filters[i].setAttribute("name", "filter");
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
        console.log(activeFilters[i].textContent);
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