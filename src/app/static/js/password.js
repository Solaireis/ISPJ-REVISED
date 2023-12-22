function passwordEventListener(passwordEl, confirmPassEl, toggleBtnEl, showSvgEl, hideSvgEl) {
    // check if the element exists
    if (!passwordEl) {
        throw new Error("Password input element not found");
    }

    toggleBtnEl.addEventListener("click", () => {
        if (passwordEl.type === "password") {
            passwordEl.type = "text";
            hideSvgEl.classList.remove("hidden");
            showSvgEl.classList.add("hidden");
        } else {
            passwordEl.type = "password";
            hideSvgEl.classList.add("hidden");
            showSvgEl.classList.remove("hidden");
        }

        if (confirmPassEl) {
            if (confirmPassEl.type === "password") {
                confirmPassEl.type = "text";
            } else {
                confirmPassEl.type = "password";
            }
        }
    });
}