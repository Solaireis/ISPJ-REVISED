/*-------------------- Start of Chat list and search logic  --------------------*/

let userList = [];
let prevChats = [];
const chatList = document.getElementById("chatList");
const userSearchInput = document.getElementById("userSearchInput");
const resetSearch = document.getElementById("resetSearch");

function searchUsers(value) {
    searchNoResults.classList.add("hidden");
    if (value == "") {
        for (const user of userList) {
            chatElement = document.getElementById(user._id);
            chatElement.classList.remove("hidden");
        }

        resetSearch.classList.add("hidden");
        return;
    }
    resetSearch.classList.remove("hidden");

    // filter the chats (client-side)
    const filteredUsers = userList.filter((user) => {
        return user.username.toLowerCase().includes(value.toLowerCase());
    });
    for (const user of filteredUsers) {
        chatElement = document.getElementById(user._id);
        chatElement.classList.remove("hidden");
    }
    for (const user of userList) {
        if (!filteredUsers.includes(user)) {
            chatElement = document.getElementById(user._id);
            chatElement.classList.add("hidden");
        }
    }
    if (filteredUsers.length == 0) {
        // no users found, show no results message
        searchNoResults.classList.remove("hidden");
    }
}

resetSearch.addEventListener("click", () => {
    userSearchInput.value = "";
    resetSearch.classList.add("hidden");
    searchNoResults.classList.add("hidden");
    searchUsers("");
});
const searchNoResults = document.getElementById("searchNoResults");
userSearchInput.addEventListener("input", (event) => {
    if (event.target.value.trim() == "") {
        event.target.value = "";
    }

    const value = event.target.value;
    searchUsers(value);
});

function processChats(chats, currentReceiverId) {
    userList = chats;

    // Keep track of the user IDs of the chats that are currently displayed in the chat list
    const displayedChats = new Set();

    // Check if the chats array has changed
    let chatsChanged = false;
    if (chats.length !== prevChats.length) {
        chatsChanged = true;
    } else {
        for (let i = 0; i < chats.length; i++) {
            const chat = chats[i];
            const prevChat = prevChats[i];
            if (
                chat._id !== prevChat._id ||
                chat.chat_id !== prevChat.chat_id ||
                chat.online !== prevChat.online ||
                chat.read !== prevChat.read ||
                chat.username !== prevChat.username ||
                chat.display_name !== prevChat.display_name ||
                chat.profile !== prevChat.profile
            ) {
                chatsChanged = true;
                break;
            }
        }
    }

    // Update the DOM if the chats array has changed
    if (chatsChanged) {
        // Update the chat list HTML
        let chatListHtml = "";
        for (let i = 0; i < chats.length; i++) {
            const chat = chats[i];
            const chatElement = document.getElementById(chat._id);
            let filteredFromSearch = false;
            if (chatElement ) {
                // if chatElement is hidden due to search, skip it
                filteredFromSearch = chatElement.classList.contains("hidden");
            }
            chatListHtml += getChatHtml(chat, currentReceiverId, filteredFromSearch);
            displayedChats.add(chat._id);
        }
        chatList.innerHTML = chatListHtml;

        // Remove chat list elements that are no longer displayed
        const chatElements = chatList.getElementsByTagName("a");
        for (let i = chatElements.length - 1; i >= 0; i--) {
            const element = chatElements[i];
            if (!displayedChats.has(element.id)) {
                element.remove();
            }
        }

        // Update the prevChats array
        prevChats = chats;
    }
}

function getOnlineStatusColour(online) {
    return online ? "bg-green-500" : "bg-gray-500";
}

const receiverOnlineHeader = document.getElementById("receiverOnlineHeader");
const userProfileLink = document.getElementById("userProfileLink");
const receiverProfileImage = document.getElementById("receiverProfileImage");
const receiverDisplayName = document.getElementById("receiverDisplayName");
const receiverUsername = document.getElementById("receiverUsername");
function getChatHtml(chat, currentReceiverId, filteredFromSearch) {
    const online = `
    <div class="absolute bg-white p-1 rounded-full bottom-0 right-0">
        <div class="${getOnlineStatusColour(chat.online)} rounded-full w-3 h-3"></div>
    </div>`;

    // if the chat is the current receiver, 
    // also indicate the online status on the top of the page
    let bgColour = "hover:bg-gray-100";
    // note that _id is the user ID
    if (chat._id == currentReceiverId) {
        bgColour = "bg-gray-200";
        const lastSlashIndex = userProfileLink.href.lastIndexOf("/") + 1;
        const updatedUserProfileLink = userProfileLink.href.substring(0, lastSlashIndex);
        if (updatedUserProfileLink != userProfileLink.href) {
            userProfileLink.href = updatedUserProfileLink + chat.username;
        }

        if (receiverOnlineHeader.innerHTML != online) {
            receiverOnlineHeader.innerHTML = online;
        }

        if (receiverProfileImage.src != chat.profile) {
            receiverProfileImage.src = chat.profile;
        }

        if (receiverDisplayName.innerText != chat.display_name) {
            // NOTE: We can use innerHtml here as it is already escaped by the server
            receiverDisplayName.innerHtml = chat.display_name;

            // update all the messages sent by this user with the new display name
            const chatMessages = document.getElementsByClassName("message-receiver");
            for (let i = 0; i < chatMessages.length; i++) {
                const chatMessage = chatMessages[i];
                if (chatMessage.innerText != chat.display_name) {
                    chatMessage.innerHtml = chat.display_name;
                }
            }
        }

        if (receiverUsername.innerText != chat.username) {
            receiverUsername.innerText = "@" + chat.username;
        }
    }

    // reduce the message to 20 characters
    const chatMsg = (chat.message.length > 20) ? chat.message.slice(0, 20) + "..." : chat.message;
    return chatHtml = `
        <a href="${chat._id}" id="${chat._id}" ${filteredFromSearch ? "class='hidden'" : ""}>
            <div class="flex justify-between items-center p-3 ${bgColour} rounded-lg relative">
                <div class="w-16 h-16 relative flex flex-shrink-0">
                    <img class="shadow-md rounded-full w-full h-full object-cover" src="${chat.profile}" alt="${chat.username} profile picture" referrerpolicy="no-referrer">
                    ${online}
                </div>
                <div class="flex-auto min-w-0 ml-4 mr-6 hidden md:block ${chat.read ? '': 'font-bold'}">
                    <p>${chat.username}</p>
                    <div class="flex items-center text-sm text-gray-600">
                        <div class="min-w-0">
                            <p class="truncate">${chatMsg}</p>
                        </div>
                        <p class="ml-2 whitespace-no-wrap" data-chatlist-timestamp="${chat.timestamp * 1000}"></p>
                    </div>
                </div>
                ${chat.read ? '' : '<div class="bg-main-100 w-3 h-3 rounded-full flex flex-shrink-0 hidden md:block"></div>'}
            </div>
        </a>
    `
}

setInterval(() => {
    const readableTimes = document.querySelectorAll("[data-chatlist-timestamp]");
    for (const readableTime of readableTimes) {
        const timestamp = parseInt(readableTime.getAttribute("data-chatlist-timestamp"));
        readableTime.innerText = getReadableTimeDiff(timestamp);
    }
}, 500);
setInterval(() => {
    const chatTimestamps = document.querySelectorAll("[data-chat-timestamp]");
    for (const chatTimestamp of chatTimestamps) {
        const timestamp = parseInt(chatTimestamp.getAttribute("data-chat-timestamp"));
        chatTimestamp.innerText = formatTimestamp(timestamp);
    }
}, 5000);

/*-------------------- End of Chat list and search logic  --------------------*/

/*-------------------- Start of functions used by the chat websocket  --------------------*/

const mainMsgDiv = document.getElementById("mainMsgDiv");
const messageArea = document.getElementById("chatArea");
const inputMsg = document.getElementById("messageText");



function getReadableFileSize(nBytes) {
    var i = nBytes == 0 ? 0 : Math.floor(Math.log(nBytes) / Math.log(1024));
    return (nBytes / Math.pow(1024, i)).toFixed(2) * 1 + " " + ["B", "kB", "MB", "GB", "TB"][i];
}

function sendMessage(ws, event) {
    event.preventDefault();
    if (!inputMsg.checkValidity()) {
        inputMsg.reportValidity();
        return;
    }

    // strip value of whitespace
    inputMsg.value = DOMPurify.sanitize(inputMsg.value.trim());
    lastMsg = inputMsg.value;

    // if the value is empty, don't send
    if (inputMsg.value == "") {
        return;
    }

    // send the JSON message
    const data = {
        message: inputMsg.value,
        md5_checksum: md5hash(inputMsg.value),
        crc32c_checksum: CRC32C.str(inputMsg.value) >>> 0,
    };
    ws.send(JSON.stringify(data));
    inputMsg.value = "";
    chatMsgFileTextInput.value = "";
    event.preventDefault();
};

function deleteMessage(ws, messageId) {
    const data = {
        delete: messageId,
    };
    ws.send(JSON.stringify(data));
    const msgDiv = document.getElementById(messageId);
    if (msgDiv) {
        msgDiv.remove();
    }
}

/*-------------------- End of functions used by the chat websocket  --------------------*/