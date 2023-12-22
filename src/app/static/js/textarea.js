function textareaAutoAdjustLogic(element, maxHeight) {
    element.style.height = "1px";
    element.style.height = (25 + element.scrollHeight) + "px";
    if (parseInt(element.style.height) >= 200) {
        element.style.height = maxHeight + "px";
    }
}

function textareaAutoAdjust(element, maxHeight) {
    element.addEventListener("input", () => textareaAutoAdjustLogic(element, maxHeight));
    element.addEventListener("focus", () => textareaAutoAdjustLogic(element, maxHeight));
}

function resetTextareaHeight(element) {
    element.style.height = "1px";
    element.style.height = (25 + element.scrollHeight) + "px";
}