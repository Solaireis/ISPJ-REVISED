/* --------------- Start of Footer Javascript --------------- */

const footerCopyrightYear = document.getElementById("copyrightYear");
if (footerCopyrightYear) {
    footerCopyrightYear.appendChild(document.createTextNode(new Date().getFullYear()));
}

/* --------------- End of Footer Javascript --------------- */

/* --------------- Start of Console Warning Javascript --------------- */

console.log("%c\
     ___                       ___           ___                 \n\
    /__/\\        ___          /  /\\         /  /\\        ___     \n\
   |  |::\\      /  /\\        /  /::\\       /  /::\\      /  /\\    \n\
   |  |:|:\\    /  /:/       /  /:/\\:\\     /  /:/\\:\\    /  /:/    \n\
 __|__|:|\\:\\  /__/::\\      /  /:/~/:/    /  /:/~/::\\  /__/::\\    \n\
/__/::::| \\:\\ \\__\\/\\:\\__  /__/:/ /:/___ /__/:/ /:/\\:\\ \\__\\/\\:\\__ \n\
\\  \\:\\~~\\__\\/    \\  \\:\\/\\ \\  \\:\\/:::::/ \\  \\:\\/:/__\\/    \\  \\:\\/\\\n\
 \\  \\:\\           \\__\\::/  \\  \\::/~~~~   \\  \\::/          \\__\\::/\n\
  \\  \\:\\          /__/:/    \\  \\:\\        \\  \\:\\          /__/:/ \n\
   \\  \\:\\         \\__\\/      \\  \\:\\        \\  \\:\\         \\__\\/  \n\
    \\__\\/                     \\__\\/         \\__\\/                \n\
",
"color: #eaa7c7; font-size: 15px; font-weight: bold;"
) // I love escape characters.

console.log(
"%c◤◢◤◢◤◢◤◢ WARNING!! ◤◢◤◢◤◢◤◢\n\
This is a browser feature intended for developers.\n\
If someone told you to share any information or to paste something here, \
it is definitely a scam and could put your account at risk of being compromised.\n\
◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢",
"color:red; font-size:20px; font-weight:bold;",
);

console.log(
"%c◤◢◤◢◤◢◤◢ NOTICE ◤◢◤◢◤◢◤◢\n\
This is for a school assignment and some features does not work like Google Sign-in!\n\
Additionally, Mirai will be closed down after a few weeks.\n\
◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢",
"color:yellow; font-size:15px; font-weight: bold;"
)

/* --------------- End of Console Warning Javascript --------------- */

/* --------------- Start of CSRF Token Retrieval Javascript --------------- */

function getCSRFToken() {
    // Initialize the CSRF token to an empty string
    let csrfToken = "";

    try {
        // Decode the cookie string
        const decodedCookie = decodeURIComponent(document.cookie);

        // Split the cookie string into an array of individual cookies
        const cookies = decodedCookie.split(";");

        // Iterate through the array of cookies
        for (const cookie of cookies) {
            // Trim any leading or trailing whitespace from the cookie
            const trimmedCookie = cookie.trim();

            // Check if the cookie has the name "csrf_token"
            if (trimmedCookie.startsWith("csrf_token=")) {
                // Extract the value of the CSRF token from the cookie
                csrfToken = trimmedCookie.substring("csrf_token=".length);
                break; // Shouldn't have more than one CSRF token cookie
            }
        }
    } catch (error) {
        // Log any errors that occurred
        console.error(error);
    }

    // Return the CSRF token
    return csrfToken;
}

/* --------------- End of CSRF Token Retrieval Javascript --------------- */

/* --------------- Start of Notification Javascript --------------- */

function notify(message) {
    document.querySelector("body").insertAdjacentHTML("afterbegin", `
    <div id="notification">
        <div class="fixed -translate-x-2/4 left-2/4 z-[60] top-12 animate-drop-down">
            <div class="border rounded bg-white text-black text-center p-3 w-48 h-24">
                ${message}
            </div>
        <div class="absolute bottom-0 w-full border-b-[3px] border-sky-500 rounded animate-sweep-right"></div>
    </div>`)

    const notification = document.getElementById("notification")
    setTimeout(() => {
        notification.firstElementChild.classList.remove("animate-drop-down")
        notification.firstElementChild.classList.add("animate-fade-out")
        setTimeout(() => notification.remove(), 750)
    }, 1750)
}

/* --------------- End of Notification Javascript --------------- */