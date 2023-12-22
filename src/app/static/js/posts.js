const randomXssQuotes = [
    "I'm a XSS Noob",
    "I tried to do a XSS attack but I am a disappointment",
    "amogus",
];
function getRandomXssQuote() {
    // since DOMPurify will santise the string, if the santised string is empty, it will return a random quote
    return randomXssQuotes[Math.floor(Math.random() * randomXssQuotes.length)];
}

function getPostHtml(postJson, userId) {
    const miraiPlus = postJson.mirai_plus ? `
        <svg viewBox="0 0 24 24" aria-label="Verified account" fill="currentColor" class="w-4 h-4 ml-1 text-main-50">
            <g>
                <path
                    d="M22.5 12.5c0-1.58-.875-2.95-2.148-3.6.154-.435.238-.905.238-1.4 0-2.21-1.71-3.998-3.818-3.998-.47 0-.92.084-1.336.25C14.818 2.415 13.51 1.5 12 1.5s-2.816.917-3.437 2.25c-.415-.165-.866-.25-1.336-.25-2.11 0-3.818 1.79-3.818 4 0 .494.083.964.237 1.4-1.272.65-2.147 2.018-2.147 3.6 0 1.495.782 2.798 1.942 3.486-.02.17-.032.34-.032.514 0 2.21 1.708 4 3.818 4 .47 0 .92-.086 1.335-.25.62 1.334 1.926 2.25 3.437 2.25 1.512 0 2.818-.916 3.437-2.25.415.163.865.248 1.336.248 2.11 0 3.818-1.79 3.818-4 0-.174-.012-.344-.033-.513 1.158-.687 1.943-1.99 1.943-3.484zm-6.616-3.334l-4.334 6.5c-.145.217-.382.334-.625.334-.143 0-.288-.04-.416-.126l-.115-.094-2.415-2.415c-.293-.293-.293-.768 0-1.06s.768-.294 1.06 0l1.77 1.767 3.825-5.74c.23-.345.696-.436 1.04-.207.346.23.44.696.21 1.04z"
                ></path>
            </g>
        </svg>
    ` : ``;
    const deleteBtn = postJson.user_id !== userId ? `` : `
        <button id="deletePost${postJson._id}" class="w-full flex items-center gap-x-3.5 py-2 px-3 rounded-md text-sm text-red-600 hover:bg-gray-100 focus:ring-2 focus:ring-blue-500">
            Delete
        </button>
    `;

    const postDesc = postJson.description ? `<p class="break-words overflow-auto text-base width-auto font-medium text-gray-800 flex-shrink whitespace-pre-wrap">${wrapUrlsInAnchorTags(DOMPurify.sanitize(postJson.description)) || getRandomXssQuote()}</p>` : ``;

    const imgViewIds = [];
    const plyrJsIds = [];
    let embedHtmls = "";
    const fileApiPrefix = "/api/posts/file/";
    if (postJson.images) {
        for (const img of postJson.images) {
            const imageViewId = `imgView#${img.blob_id}`;
            const imageUrl = fileApiPrefix + img.blob_id;
            embedHtmls += `
                <div class="flex rounded">
                    <img
                        class="w-full rounded border bg-black aspect-video object-none ${getBlurFlag(img) ? "blur" : ""}"
                        src="${imageUrl}?compress=true"
                        alt="${img.filename}"
                        id="${imageViewId}"
                    >
                </div>
            `;
            imgViewIds.push({
                elementId: imageViewId,
                url: imageUrl,
            });
        }

        if (postJson.images.length > 1) {
            embedHtmls = `<div class="grid grid-cols-2 gap-y-0 my-3">${embedHtmls}</div>`;
        } else {
            embedHtmls = `<div class="my-3">${embedHtmls}</div>`;
        }
    } else if (postJson.video) {
        for (const video of postJson.video) {
            const videoPlyrjsId = `plyr_${video.blob_id}`;
            const videoUrl = fileApiPrefix + video.blob_id;
            embedHtmls += `
                <div class="flex my-3 mr-2 rounded-2xl">
                    <video id="${videoPlyrjsId}" playsinline controls class="aspect-video w-full rounded-2xl border border-gray-600 bg-black">
                        <source src="${videoUrl}" type="${video.type}" />
                    </video>
                </div>
            `
            plyrJsIds.push({
                elementId: videoPlyrjsId,
                url: videoUrl,
            });
        }
    } else if (postJson.description !== null) {
        embedHtmls += getYoutubeUrlEmbeds(postJson.description, true);
    }

    let postLikeCount;
    if (postJson.likes) {
        postLikeCount = postJson.likes.length;
    } else {
        postLikeCount = 0;
    }

    const maxLen = 15;
    const username = postJson.username.length > maxLen ? postJson.username.substring(0, maxLen) + "..." : postJson.username;
    const displayName = postJson.display_name.length > maxLen ? postJson.display_name.substring(0, maxLen) + "..." : postJson.display_name;
    const postHtml = `
        <div class="border-b border-gray-200 hover:bg-gray-100 cursor-pointer transition duration-350 ease-in-out pb-4 border-l border-r">
            <div class="flex flex-shrink-0 p-4 pb-0">
                <a href="/${postJson.username}/post/${postJson._id}" class="flex-shrink-0 group block">
                    <div class="flex items-top">
                        <div>
                            <img class="inline-block h-9 w-9 rounded-full user-profile-img"
                                src="${postJson.profile_image}"
                                alt="@${postJson.username} profile picture"
                            >
                        </div>
                        <div class="ml-3">
                            <p class="flex items-center text-base leading-6 font-medium text-gray-800">
                                ${displayName}
                                <!--Mirai+ Mark-->
                                ${miraiPlus}
                                <span class="ml-1 text-sm leading-5 font-medium text-gray-500 group-hover:text-gray-400 transition ease-in-out duration-150">
                                    @${username} . <span data-post-timestamp="${postJson.timestamp * 1000}">${formatTimestamp(postJson.timestamp * 1000)}</span>
                                </span>
                            </p>
                        </div>
                    </div>
                </a>

                <div class="hs-dropdown ml-auto relative inline-flex [--strategy:absolute]">
                    <button id="postDropdownButton${postJson._id}" type="button" class="hs-dropdown-toggle flex ml-auto class="w-14 xl:w-full mx-auto mt-auto flex flex-row justify-between mb-5 rounded-full hover:bg-pink-100 p-2 cursor-pointer transition duration-350 ease-in-out mb-2">
                        <span class="sr-only">Open profile dropdown</span>
                        <svg class="h-4 w-4 mr-2" aria-hidden="true" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                            <path d="M6 10a2 2 0 11-4 0 2 2 0 014 0zM12 10a2 2 0 11-4 0 2 2 0 014 0zM16 12a2 2 0 100-4 2 2 0 000 4z"></path>
                        </svg>
                    </button>

                    <div class="hs-dropdown-menu w-72 transition-[opacity,margin] duration hs-dropdown-open:opacity-100 opacity-0 hidden z-10 top-0 right-0 left-auto lg:right-auto lg:left-0 min-w-[16.5rem] bg-white shadow-md rounded-lg p-2 mt-2 dark:bg-gray-800 dark:border dark:border-gray-700 dark:divide-gray-700" aria-labelledby="postDropdownButton${postJson._id}">
                        <button id="copyToClipboard${postJson._id}" class="w-full flex items-center gap-x-3.5 py-2 px-3 rounded-md text-sm text-gray-800 hover:bg-gray-100 focus:ring-2 focus:ring-blue-500 dark:text-gray-400 dark:hover:bg-gray-700 dark:hover:text-gray-300">
                            Share
                        </button>
                        ${deleteBtn}
                    </div>
                </div>
            </div>
            <div class="px-16">
                ${postDesc}
                ${embedHtmls}
                <!--Statistics (Likes, comments)-->
                <div class="flex">
                    <div class="w-full">
                        <div class="flex items-center">
                            <a class="ml-auto" href="/${postJson.username}/post/${postJson._id}">
                                <div class="flex-1 flex items-center text-gray-800 text-xs hover:text-main-50 transition duration-350 ease-in-out"> 
                                    <svg viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5 mr-2">
                                        <g>
                                            <path
                                                d="M14.046 2.242l-4.148-.01h-.002c-4.374 0-7.8 3.427-7.8 7.802 0 4.098 3.186 7.206 7.465 7.37v3.828c0 .108.044.286.12.403.142.225.384.347.632.347.138 0 .277-.038.402-.118.264-.168 6.473-4.14 8.088-5.506 1.902-1.61 3.04-3.97 3.043-6.312v-.017c-.006-4.367-3.43-7.787-7.8-7.788zm3.787 12.972c-1.134.96-4.862 3.405-6.772 4.643V16.67c0-.414-.335-.75-.75-.75h-.396c-3.66 0-6.318-2.476-6.318-5.886 0-3.534 2.768-6.302 6.3-6.302l4.147.01h.002c3.532 0 6.3 2.766 6.302 6.296-.003 1.91-.942 3.844-2.514 5.176z"
                                            ></path>
                                        </g>
                                    </svg>
                                </div>
                            </a>
                            <button id="likeButton${postJson._id}">
                                <div class="flex-1 flex items-center text-gray-800 text-xs hover:text-red-600 transition duration-350 ease-in-out">
                                    <svg id="heartButton${postJson._id}" viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5 mr-2">
                                        <g>
                                            <path
                                                d="M12 21.638h-.014C9.403 21.59 1.95 14.856 1.95 8.478c0-3.064 2.525-5.754 5.403-5.754 2.29 0 3.83 1.58 4.646 2.73.814-1.148 2.354-2.73 4.645-2.73 2.88 0 5.404 2.69 5.404 5.755 0 6.376-7.454 13.11-10.037 13.157H12zM7.354 4.225c-2.08 0-3.903 1.988-3.903 4.255 0 5.74 7.034 11.596 8.55 11.658 1.518-.062 8.55-5.917 8.55-11.658 0-2.267-1.823-4.255-3.903-4.255-2.528 0-3.94 2.936-3.952 2.965-.23.562-1.156.562-1.387 0-.014-.03-1.425-2.965-3.954-2.965z"
                                            ></path>
                                        </g>
                                    </svg>
                                    <span id="likeCount${postJson._id}">${postLikeCount}</span>
                                </div>
                            </button>
                            <!--div class="flex-1 flex items-center text-gray-800 text-xs hover:text-main-50 transition duration-350 ease-in-out">
                                <svg viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5 mr-2">
                                    <g>
                                        <path
                                            d="M17.53 7.47l-5-5c-.293-.293-.768-.293-1.06 0l-5 5c-.294.293-.294.768 0 1.06s.767.294 1.06 0l3.72-3.72V15c0 .414.336.75.75.75s.75-.336.75-.75V4.81l3.72 3.72c.146.147.338.22.53.22s.384-.072.53-.22c.293-.293.293-.767 0-1.06z"
                                        ></path>
                                        <path
                                            d="M19.708 21.944H4.292C3.028 21.944 2 20.916 2 19.652V14c0-.414.336-.75.75-.75s.75.336.75.75v5.652c0 .437.355.792.792.792h15.416c.437 0 .792-.355.792-.792V14c0-.414.336-.75.75-.75s.75.336.75.75v5.652c0 1.264-1.028 2.292-2.292 2.292z"
                                        ></path>
                                    </g>
                                </svg>
                            </div-->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    return {
        html: postHtml,
        imgViewIds: imgViewIds,
        plyrJsIds: plyrJsIds,
    }
}

function getIndivPostHtml(postJson) {
    const miraiPlus = postJson.mirai_plus ? `
        <svg viewBox="0 0 24 24" aria-label="Verified account" fill="currentColor" class="w-4 h-4 ml-1 text-main-50">
            <g>
                <path
                    d="M22.5 12.5c0-1.58-.875-2.95-2.148-3.6.154-.435.238-.905.238-1.4 0-2.21-1.71-3.998-3.818-3.998-.47 0-.92.084-1.336.25C14.818 2.415 13.51 1.5 12 1.5s-2.816.917-3.437 2.25c-.415-.165-.866-.25-1.336-.25-2.11 0-3.818 1.79-3.818 4 0 .494.083.964.237 1.4-1.272.65-2.147 2.018-2.147 3.6 0 1.495.782 2.798 1.942 3.486-.02.17-.032.34-.032.514 0 2.21 1.708 4 3.818 4 .47 0 .92-.086 1.335-.25.62 1.334 1.926 2.25 3.437 2.25 1.512 0 2.818-.916 3.437-2.25.415.163.865.248 1.336.248 2.11 0 3.818-1.79 3.818-4 0-.174-.012-.344-.033-.513 1.158-.687 1.943-1.99 1.943-3.484zm-6.616-3.334l-4.334 6.5c-.145.217-.382.334-.625.334-.143 0-.288-.04-.416-.126l-.115-.094-2.415-2.415c-.293-.293-.293-.768 0-1.06s.768-.294 1.06 0l1.77 1.767 3.825-5.74c.23-.345.696-.436 1.04-.207.346.23.44.696.21 1.04z"
                ></path>
            </g>
        </svg>
    ` : ``;

    const postDesc = postJson.description ? `<p class="break-words overflow-auto text-base width-auto font-medium text-gray-800 flex-shrink whitespace-pre-wrap">${wrapUrlsInAnchorTags(DOMPurify.sanitize(postJson.description)) || getRandomXssQuote()}</p>` : ``;

    const imgViewIds = [];
    const plyrJsIds = [];
    let embedHtmls = "";
    const fileApiPrefix = "/api/posts/file/";
    if (postJson.images) {
        for (const img of postJson.images) {
            const imageViewId = `imgView#${img.blob_id}`;
            const imageUrl = fileApiPrefix + img.blob_id;
            embedHtmls += `
                <div class="flex rounded">
                    <img
                        class="w-full rounded border bg-black aspect-video object-none ${getBlurFlag(img) ? "blur" : ""}"
                        src="${imageUrl}?compress=true"
                        alt="${img.filename}"
                        id="${imageViewId}"
                    >
                </div>
            `;
            imgViewIds.push({
                elementId: imageViewId,
                url: imageUrl,
            });
        }

        if (postJson.images.length > 1) {
            embedHtmls = `<div class="grid grid-cols-2 gap-y-0 my-3">${embedHtmls}</div>`;
        } else {
            embedHtmls = `<div class="my-3">${embedHtmls}</div>`;
        }
    } else if (postJson.video) {
        for (const video of postJson.video) {
            const videoPlyrjsId = `plyr_${video.blob_id}`;
            const videoUrl = fileApiPrefix + video.blob_id;
            embedHtmls += `
                <div class="flex my-3 mr-2 rounded-2xl">
                    <video id="${videoPlyrjsId}" playsinline controls class="aspect-video w-full rounded-2xl border border-gray-600 bg-black">
                        <source src="${videoUrl}" type="${video.type}" />
                    </video>
                </div>
            `
            plyrJsIds.push({
                elementId: videoPlyrjsId,
                url: videoUrl,
            });
        }
    } else if (postJson.description) {
        embedHtmls += getYoutubeUrlEmbeds(postJson.description, true);
    }

    let postLikeCount;
    if (postJson.likes) {
        postLikeCount = postJson.likes.length;
    } else {
        postLikeCount = 0;
    }
    const maxLen = 15;
    const username = postJson.username.length > maxLen ? postJson.username.substring(0, maxLen) + "..." : postJson.username;
    const displayName = postJson.display_name.length > maxLen ? postJson.display_name.substring(0, maxLen) + "..." : postJson.display_name;
    const postHtml = `
        <div class="border-b border-gray-200 hover:bg-gray-100 cursor-pointer transition duration-350 ease-in-out pb-4 border-l border-r">
            <div class="flex flex-shrink-0 p-4 pb-0">
                <a href="/profile/${postJson.username}" class="flex-shrink-0 group block">
                    <div class="flex items-top">
                        <div>
                            <img
                                class="inline-block h-9 w-9 rounded-full"
                                src="${postJson.profile_image}"
                                alt="@${postJson.username} profile picture"
                            />
                        </div>
                        <div class="ml-3">
                            <p
                                class="flex items-center text-base leading-6 font-medium text-gray-800 "
                            >
                                ${displayName}
                                <!--Mirai+ Mark-->
                                ${miraiPlus}
                            </p>
                            <p
                            class="flex items-center text-base leading-6 font-medium text-gray-800 "
                            >
                                <span
                                    class="text-sm leading-5 font-medium text-gray-400 group-hover:text-gray-300 transition ease-in-out duration-150"
                                >
                                    @${username}
                                </span>
                            </p>
                        </div>
                    </div>
                </a>
                <button class="flex ml-auto class="w-14 xl:w-full mx-auto mt-auto flex flex-row justify-between mb-5 rounded-full hover:bg-pink-100 p-2 cursor-pointer transition duration-350 ease-in-out mb-2" data-dropdown-toggle="postDropdown"">
                    <div class="block">
                        <div class="flex items-center h-full text-gray-800">
                            <span class="sr-only">Open profile dropdown</span>
                            <svg class="h-4 w-4 mr-2" aria-hidden="true" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                <path d="M6 10a2 2 0 11-4 0 2 2 0 014 0zM12 10a2 2 0 11-4 0 2 2 0 014 0zM16 12a2 2 0 100-4 2 2 0 000 4z"></path>
                            </svg>
                        </div>
                    </div>
                </button>
            </div>
            <div>
                <div class="mt-4 p-4">
                    ${postDesc}
                    ${embedHtmls}
                    <span class="text-gray-400 group-hover:text-gray-300 transition ease-in-out duration-150"><span data-post-timestamp="${postJson.timestamp * 1000}">${formatTimestamp(postJson.timestamp * 1000)}</span></span>
                    <hr class="my-4">
                    <div class="flex">
                        <div class="flex items-center">
                            <!--p>0 <span class="text-gray-400 group-hover:text-gray-300 transition ease-in-out duration-150">Comments</span></p-->
                        </div>
                        <div class="ml-3 flex items-center">
                            <p><span id="likeCounter">${postLikeCount}</span> <span class="text-gray-400 group-hover:text-gray-300 transition ease-in-out duration-150">Likes</span></p>
                        </div>
                    </div>
                    <hr class="my-4">

                    <!--Statistics (Likes, comments)-->
                    <div class="flex">
                        <div class="w-full">
                            <div class="flex items-center">
                                <div id="postLike" class="flex-1 flex items-center text-gray-800 text-xs text-gray-400 hover:text-red-600 transition duration-350 ease-in-out">
                                    <svg
                                        id ="heartButton"
                                        viewBox="0 0 24 24"
                                        fill="currentColor"
                                        class="w-5 h-5 mr-2"
                                    >
                                        <g>
                                            <path
                                                d="M12 21.638h-.014C9.403 21.59 1.95 14.856 1.95 8.478c0-3.064 2.525-5.754 5.403-5.754 2.29 0 3.83 1.58 4.646 2.73.814-1.148 2.354-2.73 4.645-2.73 2.88 0 5.404 2.69 5.404 5.755 0 6.376-7.454 13.11-10.037 13.157H12zM7.354 4.225c-2.08 0-3.903 1.988-3.903 4.255 0 5.74 7.034 11.596 8.55 11.658 1.518-.062 8.55-5.917 8.55-11.658 0-2.267-1.823-4.255-3.903-4.255-2.528 0-3.94 2.936-3.952 2.965-.23.562-1.156.562-1.387 0-.014-.03-1.425-2.965-3.954-2.965z"
                                            ></path>
                                        </g>
                                    </svg>
                                    <span id="likeCount">${postLikeCount}</span>
                                </div>
                                <div id="copyToClipboard" class="flex-1 flex items-center text-gray-800 text-xs text-gray-400 hover:text-blue-400 transition duration-350 ease-in-out">
                                    <svg
                                        viewBox="0 0 24 24"
                                        fill="currentColor"
                                        class="w-5 h-5 mr-2"
                                    >
                                        <g>
                                            <path
                                                d="M17.53 7.47l-5-5c-.293-.293-.768-.293-1.06 0l-5 5c-.294.293-.294.768 0 1.06s.767.294 1.06 0l3.72-3.72V15c0 .414.336.75.75.75s.75-.336.75-.75V4.81l3.72 3.72c.146.147.338.22.53.22s.384-.072.53-.22c.293-.293.293-.767 0-1.06z"
                                            ></path>
                                            <path
                                                d="M19.708 21.944H4.292C3.028 21.944 2 20.916 2 19.652V14c0-.414.336-.75.75-.75s.75.336.75.75v5.652c0 .437.355.792.792.792h15.416c.437 0 .792-.355.792-.792V14c0-.414.336-.75.75-.75s.75.336.75.75v5.652c0 1.264-1.028 2.292-2.292 2.292z"
                                            ></path>
                                        </g>
                                    </svg>
                                </div>
                            </div>
                        </div>
                    </div>
                    <!--/Statistics (Likes, comments)-->
                </div>
                <!-- /Post Description and Image-->
            </div>
        </div>
    `;
    return {
        html: postHtml,
        imgViewIds: imgViewIds,
        plyrJsIds: plyrJsIds,
    }
}

function getCommentsHtml(postJson, userId) {
    const miraiPlus = postJson.mirai_plus ? `
        <svg viewBox="0 0 24 24" aria-label="Verified account" fill="currentColor" class="w-4 h-4 ml-1 text-main-50">
            <g>
                <path
                    d="M22.5 12.5c0-1.58-.875-2.95-2.148-3.6.154-.435.238-.905.238-1.4 0-2.21-1.71-3.998-3.818-3.998-.47 0-.92.084-1.336.25C14.818 2.415 13.51 1.5 12 1.5s-2.816.917-3.437 2.25c-.415-.165-.866-.25-1.336-.25-2.11 0-3.818 1.79-3.818 4 0 .494.083.964.237 1.4-1.272.65-2.147 2.018-2.147 3.6 0 1.495.782 2.798 1.942 3.486-.02.17-.032.34-.032.514 0 2.21 1.708 4 3.818 4 .47 0 .92-.086 1.335-.25.62 1.334 1.926 2.25 3.437 2.25 1.512 0 2.818-.916 3.437-2.25.415.163.865.248 1.336.248 2.11 0 3.818-1.79 3.818-4 0-.174-.012-.344-.033-.513 1.158-.687 1.943-1.99 1.943-3.484zm-6.616-3.334l-4.334 6.5c-.145.217-.382.334-.625.334-.143 0-.288-.04-.416-.126l-.115-.094-2.415-2.415c-.293-.293-.293-.768 0-1.06s.768-.294 1.06 0l1.77 1.767 3.825-5.74c.23-.345.696-.436 1.04-.207.346.23.44.696.21 1.04z"
                ></path>
            </g>
        </svg>
    ` : ``;

    const deleteBtn = postJson.user_id !== userId ? `` : `
        <button id="deleteComment${postJson._id}" class="w-full flex items-center gap-x-3.5 py-2 px-3 rounded-md text-sm text-red-600 hover:bg-gray-100 focus:ring-2 focus:ring-blue-500">
            Delete
        </button>
    `;

    const postDesc = postJson.description ? `<p class="text-base width-auto font-medium text-gray-800 flex-shrink whitespace-pre-wrap">${wrapUrlsInAnchorTags(DOMPurify.sanitize(postJson.description)) || getRandomXssQuote()}</p>` : ``;

    const imgViewIds = [];
    const plyrJsIds = [];
    let embedHtmls = "";
    const fileApiPrefix = "/api/posts/file/";
    if (postJson.images) {
        for (const img of postJson.images) {
            const imageViewId = `imgView#${img.blob_id}`;
            const imageUrl = fileApiPrefix + img.blob_id;
            embedHtmls += `
                <div class="flex rounded">
                    <img
                        class="w-full rounded border bg-black aspect-video object-none ${getBlurFlag(img) ? "blur" : ""}"
                        src="${imageUrl}?compress=true"
                        alt="${img.filename}"
                        id="${imageViewId}"
                    >
                </div>
            `;
            imgViewIds.push({
                elementId: imageViewId,
                url: imageUrl,
            });
        }

        if (postJson.images.length > 1) {
            embedHtmls = `<div class="grid grid-cols-2 gap-y-0 my-3">${embedHtmls}</div>`;
        } else {
            embedHtmls = `<div class="my-3">${embedHtmls}</div>`;
        }
    } else if (postJson.video) {
        for (const video of postJson.video) {
            const videoPlyrjsId = `plyr_${video.blob_id}`;
            const videoUrl = fileApiPrefix + video.blob_id;
            embedHtmls += `
                <div class="flex my-3 mr-2 rounded-2xl">
                    <video id="${videoPlyrjsId}" playsinline controls class="aspect-video w-full rounded-2xl border border-gray-600 bg-black">
                        <source src="${videoUrl}" type="${video.type}" />
                    </video>
                </div>
            `
            plyrJsIds.push({
                elementId: videoPlyrjsId,
                url: videoUrl,
            });
        }
    } else if (postJson.description) {
        embedHtmls += getYoutubeUrlEmbeds(postJson.description, true);
    }

    let postLikeCount;
    if (postJson.likes) {
        postLikeCount = postJson.likes.length;
    } else {
        postLikeCount = 0;
    }

    const maxLen = 15;
    const username = postJson.username.length > maxLen ? postJson.username.substring(0, maxLen) + "..." : postJson.username;
    const displayName = postJson.display_name.length > maxLen ? postJson.display_name.substring(0, maxLen) + "..." : postJson.display_name;
    const postHtml = `
        <div class="border-b border-gray-200 hover:bg-gray-100 cursor-pointer transition duration-350 ease-in-out pb-4 border-l border-r">
            <div class="flex flex-shrink-0 p-4 pb-0">
                <a href="/${postJson.post_username ? postJson.post_username + '/' : ''}post/${postJson.post_id}" class="flex-shrink-0 group block">
                    <div class="flex items-top">
                        <div>
                            <img class="inline-block h-9 w-9 rounded-full user-profile-img"
                                src="${postJson.profile_image}"
                                alt="@${postJson.username} profile picture"
                            >
                        </div>
                        <div class="ml-3">
                            <p class="flex items-center text-base leading-6 font-medium text-gray-800">
                                ${displayName}
                                <!--Mirai+ Mark-->
                                ${miraiPlus}
                                <span class="ml-1 text-sm leading-5 font-medium text-gray-500 group-hover:text-gray-400 transition ease-in-out duration-150">
                                    @${username} . <span data-post-timestamp="${postJson.timestamp * 1000}">${formatTimestamp(postJson.timestamp * 1000)}</span>
                                </span>
                            </p>
                        </div>
                    </div>
                </a>
                <div class="hs-dropdown ml-auto relative inline-flex [--strategy:absolute]">
                    <button id="postDropdownButton${postJson._id}" type="button" class="hs-dropdown-toggle flex ml-auto class="w-14 xl:w-full mx-auto mt-auto flex flex-row justify-between mb-5 rounded-full hover:bg-pink-100 p-2 cursor-pointer transition duration-350 ease-in-out mb-2">
                        <span class="sr-only">Open profile dropdown</span>
                        <svg class="h-4 w-4 mr-2" aria-hidden="true" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                            <path d="M6 10a2 2 0 11-4 0 2 2 0 014 0zM12 10a2 2 0 11-4 0 2 2 0 014 0zM16 12a2 2 0 100-4 2 2 0 000 4z"></path>
                        </svg>
                    </button>

                    <div class="hs-dropdown-menu w-72 transition-[opacity,margin] duration hs-dropdown-open:opacity-100 opacity-0 hidden z-10 top-0 right-0 left-auto lg:right-auto lg:left-0 min-w-[16.5rem] bg-white shadow-md rounded-lg p-2 mt-2 dark:bg-gray-800 dark:border dark:border-gray-700 dark:divide-gray-700" aria-labelledby="postDropdownButton${postJson._id}">
                        <button id="copyCommentToClipboard${postJson._id}" class="w-full flex items-center gap-x-3.5 py-2 px-3 rounded-md text-sm text-gray-800 hover:bg-gray-100 focus:ring-2 focus:ring-blue-500 dark:text-gray-400 dark:hover:bg-gray-700 dark:hover:text-gray-300">
                            Share
                        </button>
                        ${deleteBtn}
                    </div>
                </div>
            </div>
            <div class="px-16">
                ${postDesc}
                ${embedHtmls}
                <!--Statistics (Likes, comments)-->
                <div class="flex">
                    <div class="w-full">
                        <div class="flex items-center">
                            <button class="ml-auto" id="likeButton${postJson._id}">
                                <div class="flex-1 flex items-center text-gray-800 text-xs hover:text-red-600 transition duration-350 ease-in-out">
                                    <svg id="heartButton${postJson._id}" viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5 mr-2">
                                        <g>
                                            <path
                                                d="M12 21.638h-.014C9.403 21.59 1.95 14.856 1.95 8.478c0-3.064 2.525-5.754 5.403-5.754 2.29 0 3.83 1.58 4.646 2.73.814-1.148 2.354-2.73 4.645-2.73 2.88 0 5.404 2.69 5.404 5.755 0 6.376-7.454 13.11-10.037 13.157H12zM7.354 4.225c-2.08 0-3.903 1.988-3.903 4.255 0 5.74 7.034 11.596 8.55 11.658 1.518-.062 8.55-5.917 8.55-11.658 0-2.267-1.823-4.255-3.903-4.255-2.528 0-3.94 2.936-3.952 2.965-.23.562-1.156.562-1.387 0-.014-.03-1.425-2.965-3.954-2.965z"
                                            ></path>
                                        </g>
                                    </svg>
                                    <span id="likeCounter${postJson._id}">${postLikeCount}</span>
                                </div>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    return {
        html: postHtml,
        imgViewIds: imgViewIds,
        plyrJsIds: plyrJsIds,
    }
}

setInterval(() => {
    const chatTimestamps = document.querySelectorAll("[data-post-timestamp]");
    for (const chatTimestamp of chatTimestamps) {
        const timestamp = parseInt(chatTimestamp.getAttribute("data-post-timestamp"));
        chatTimestamp.innerText = formatTimestamp(timestamp);
    }
}, 30 * 60 * 1000); // 30 mins