function parseChatNoti(chatJson) {
    let contentHtml = `
        <li class="py-3 sm:py-4">
            <a href="/chat" class="flex items-center space-x-4">
                <div class="flex-shrink-0">
                    <svg fill="currentColor" viewBox="0 0 24 24" class="text-main-50 h-10 w-10 animate-bounce">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.25 3.018H4.75C3.233 3.018 2 4.252 2 5.77v12.495c0 1.518 1.233 2.753 2.75 2.753h14.5c1.517 0 2.75-1.235 2.75-2.753V5.77c0-1.518-1.233-2.752-2.75-2.752zm-14.5 1.5h14.5c.69 0 1.25.56 1.25 1.25v.714l-8.05 5.367c-.273.18-.626.182-.9-.002L3.5 6.482v-.714c0-.69.56-1.25 1.25-1.25zm14.5 14.998H4.75c-.69 0-1.25-.56-1.25-1.25V8.24l7.24 4.83c.383.256.822.384 1.26.384.44 0 .877-.128 1.26-.383l7.24-4.83v10.022c0 .69-.56 1.25-1.25 1.25z"></path>
                    </svg>
                </div>
                <div class="flex-1 min-w-0">
                    <div class="w-full flex divide-x-2">
    `;

    const chatUsers = chatJson.users.length > 3 ? chatJson.users.slice(0, 3) : chatJson.users;
    for (const user of chatUsers) {
        contentHtml += `<img class="w-8 h-8 mr-1 rounded-full" src="${user.profile_image}" alt="@${user.username} profile picture">`;
    };

    return `${contentHtml}
                    </div>
                    <p class="text-sm mt-1 font-medium text-gray-900 truncate">
                        ${chatJson.message}
                    </p>
                </div> 
            </a>
        </li>
    `;
}

function getNotifSvgHtml(type, read) {
    if (type == "follow") {
        return `
            <svg viewBox="0 0 24 24" aria-hidden="true" fill="currentColor" class="text-main-50 h-10 w-10 ${read ? '' : 'animate-bounce'}">
                <g>
                    <path d="M17.863 13.44c1.477 1.58 2.366 3.8 2.632 6.46l.11 1.1H3.395l.11-1.1c.266-2.66 1.155-4.88 2.632-6.46C7.627 11.85 9.648 11 12 11s4.373.85 5.863 2.44zM12 2C9.791 2 8 3.79 8 6s1.791 4 4 4 4-1.79 4-4-1.791-4-4-4z"></path>
                </g>
            </svg>
        `;
    }
    // likes
    return `
        <svg class="text-red-600 h-10 w-10 ${read ? '' : 'animate-bounce'}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="currentColor">
            <path d="M0 190.9V185.1C0 115.2 50.52 55.58 119.4 44.1C164.1 36.51 211.4 51.37 244 84.02L256 96L267.1 84.02C300.6 51.37 347 36.51 392.6 44.1C461.5 55.58 512 115.2 512 185.1V190.9C512 232.4 494.8 272.1 464.4 300.4L283.7 469.1C276.2 476.1 266.3 480 256 480C245.7 480 235.8 476.1 228.3 469.1L47.59 300.4C17.23 272.1 .0003 232.4 .0003 190.9L0 190.9z"/>
        </svg>
    `;
}

function parseNotif(notifiJson) {
    return `
        <li class="py-3 sm:py-4">
            <a href="${notifiJson.link}" class="flex items-center space-x-4">
                <div class="flex-shrink-0">
                    ${getNotifSvgHtml(notifiJson.type, notifiJson.read)}
                </div>
                <div class="flex-1 min-w-0">
                    <img class="w-14 h-14 rounded-full" src="${notifiJson.profile_image}" alt="@${notifiJson.username} profile picture">
                    <p class="text-sm mt-1 font-medium text-gray-900 truncate">
                        ${notifiJson.message}
                    </p>
                </div> 
            </a>
        </li>
    `;
}