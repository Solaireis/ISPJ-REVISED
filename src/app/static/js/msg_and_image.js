/*-------------------- Start of Image and Delete Message Modal --------------------*/

const imageViewModal = document.getElementById("imageViewModal");
const modalImgSrc = document.getElementById("modalImageSrc");
const imageViewOriginalSrc = document.getElementById("imageViewOriginalSrc");
const imgViewCloseBtn = document.getElementById("imageViewClose");

// this function is called when a small image is clicked
function showImgModal(src) {
    imageViewModal.classList.remove("hidden");
    modalImgSrc.src = src + "?compress=true";
    imageViewOriginalSrc.href = src;
}
// this function is called when the close button is clicked
if (imgViewCloseBtn) {
    imgViewCloseBtn.addEventListener("click", () => {
        imageViewModal.classList.add("hidden");
    });
}

const deleteMsgModal = document.getElementById("deleteMsgModal");
const deleteMsgButton = document.getElementById("deleteMsgButton");
const closeDeleteMsgModal = document.querySelectorAll(".closeDeleteMsgModal");

// this function is called when the delete button is clicked
function showDeleteMsgModal(ws, messageId) {
    deleteMsgModal.classList.remove("hidden");
    deleteMsgButton.addEventListener("click", () => {
        deleteMessage(ws, messageId);
        deleteMsgModal.classList.add("hidden");
    });
}

// this function is called when the close button is clicked
closeDeleteMsgModal.forEach((btn) => {
    btn.addEventListener("click", () => {
        deleteMsgModal.classList.add("hidden");
    });
});

// this function is called when the user clicks anywhere outside of the modal
window.onclick = (e) => {
    if (deleteMsgModal && e.target == deleteMsgModal) {
        deleteMsgModal.classList.add("hidden");
    } else if (imageViewModal && e.target == imageViewModal) {
        imageViewModal.classList.add("hidden");
    }
}

function getBlurFlag(imageJson) {
    let blur = false || imageJson.spoiler;
    if (!blur && (blursexualImages || blurViolentImages || blurMemeImages)) {
        const safeAnnotation = imageJson.safe_search_annotation;
        for (const key in safeAnnotation) {
            if (
                ((key == "adult" || key == "racy") && blursexualImages) || 
                (key == "violence" && blurViolentImages) || 
                (key == "spoof" && blurMemeImages)
            ) {
                if (safeAnnotation[key] == "VERY_LIKELY") {
                    blur = true;
                    break;
                }
            }
        }
    }
    return blur;
}

function addImgEvent(imgArr) {
    if (!imgArr) 
        return;

    for (const imageObj of imgArr) {
        const img = document.getElementById(imageObj.elementId);
        img.addEventListener("click", () => {
            showImgModal(imageObj.url);
        });
    }
}

/*-------------------- End of Image and Delete Message Modal --------------------*/