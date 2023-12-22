function getReadableTimeDiff(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    const diffDays = Math.floor(diff / (1000 * 3600 * 24));
    const diffHours = Math.floor(diff / (1000 * 3600));
    const diffMinutes = Math.floor(diff / (1000 * 60));
    const diffSeconds = Math.floor(diff / 1000);

    if (diffDays > 3) {
        return date.toLocaleDateString("en-US");
    } else if (diffDays > 0) {
        return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
    } else if (diffHours > 0) {
        return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
    } else if (diffMinutes > 0) {
        return `${diffMinutes} minute${diffMinutes > 1 ? "s" : ""} ago`;
    } else if (diffSeconds > 0) {
        return `${diffSeconds} second${diffSeconds > 1 ? "s" : ""} ago`;
    } else {
        return "Just now";
    }
}

function getTimeStrFromDate(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString(
        "en-US", 
        {
            hour: "numeric",
            minute: "numeric",
            hour12: true,
        },
    );
}

function getDateFromTimestamp(timestamp, withTime = false) {
    const date = new Date(timestamp);
    if (!withTime) {
        return date.toLocaleDateString("en-US");
    }
    return date.toLocaleString(
        "en-US",
        {
            year: "numeric",
            month: "long",
            day: "numeric",
            hour: "numeric",
            minute: "numeric",
            second: "numeric",
            hour12: true,
        },
    );
}

function formatDate(timestamp) {
    // check if dateObj is today
    const date = new Date(timestamp);
    const today = new Date();
    if (
        date.getDate() == today.getDate() &&
        date.getMonth() == today.getMonth() &&
        date.getFullYear() == today.getFullYear()
    ) {
        return "Today";
    }

    const yyyy = date.getFullYear();
    let mm = date.getMonth() + 1; // Months start at 0!
    let dd = date.getDate();

    if (dd < 10) 
        dd = "0" + dd;
    if (mm < 10) 
        mm = "0" + mm;

    return dd + "/" + mm + "/" + yyyy;
}

function formatTimestamp(timestamp, getWholeDate = false) {
    const date = formatDate(timestamp);
    return (date === "Today" && !getWholeDate) ? getTimeStrFromDate(timestamp) : date + ", " + getTimeStrFromDate(timestamp);
}