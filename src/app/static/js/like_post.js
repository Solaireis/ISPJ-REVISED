const setAsLiked = (heartButtonEl, likeCountEl) => {
    heartButtonEl.style.fill="red";
    likeCountEl.classList.add("text-red-600");
}

const setAsUnliked = (heartButtonEl, likeCountEl) => {
    heartButtonEl.style.fill="currentColor";
    likeCountEl.classList.remove("text-red-600");
}

const addLike = (heartButtonEl, likeCountEl, likeCounterEL) => {
    likeCountEl.innerHTML = parseInt(likeCountEl.innerHTML) + 1;
    if (likeCounterEL) {likeCounterEL.innerHTML = parseInt(likeCounterEL.innerHTML) + 1;}
    setAsLiked(heartButtonEl, likeCountEl);
}

const removeLike = (heartButtonEl, likeCountEl, likeCounterEL) => {
    likeCountEl.innerHTML = parseInt(likeCountEl.innerHTML) - 1;
    if (likeCounterEL) {likeCounterEL.innerHTML = parseInt(likeCounterEL.innerHTML) - 1;}
    setAsUnliked(heartButtonEl, likeCountEl);
}