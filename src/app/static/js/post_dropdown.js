const deleteFunc = async (id) => {
    const res = await fetch("/api/delete/post", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": getCSRFToken(),
        },
        body: JSON.stringify({
            post_id: id,
        }),
    });
    if (res.ok) {
        notify("Post deleted!");
        postDiv.removeChild(document.getElementById(id));
    };
};

const deleteCommentFunc = async (id, divEl) => {
    const res = await fetch("/api/delete/comment", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": getCSRFToken(),
        },
        body: JSON.stringify({
            post_id: id,
        }),
    });
    if (res.ok) {
        notify("Comment deleted!");
        location.reload();
        //divEl.removeChild(document.getElementById(id));
    };
};

const copyFunc = async (username, post_id) => {
    navigator.clipboard.writeText(`${location.origin}/${username}/post/${post_id}`);
    notify("Link copied to clipboard");
}