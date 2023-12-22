const username = document.getElementById("username");
const description = document.getElementById("description");
const location = document.getElementById("location");
const website = document.getElementById("website");
const urlRegex = /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g;

document.getElementById("onSubmitEdit").onclick = async () => {
    const usernameVal = username.value;
    const descriptionVal = description.value;
    const locationVal = location.value;
    const websiteVal = website.value;
    const validLink = urlRegex.test(websiteVal);

    if (validLink == false) {
        notify("Please enter a valid URL");
        return;
    }

    const data = {
        username: usernameVal,
        description: descriptionVal,
        location: locationVal,
        website: websiteVal,
    };
    res = await fetch("{{ url_for('edit_profile') }}", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": getCSRFToken(),
        },
        body: JSON.stringify(data)
    });
    json = await res.json();
    document.location.reload();
}