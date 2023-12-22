const embedSpacing = "my-4";

const twitterPostRegex = /https?:\/\/(?:www\.)?twitter\.com\/(?:#!\/)?(\w+)\/status(es)?\/(\d+)/g;
function getTwitterPostEmbeds(msgId, text) {
    let embedHtmls = "";
    let alrdEmbedded = new Set();
    const twitterPostIds = [];

    // Find all Twitter posts in the text
    twitterPostUrls = text.match(twitterPostRegex);
    if (!twitterPostUrls) {
        return [embedHtmls, twitterPostIds];
    }
    let counter = 0;
    for (const url of twitterPostUrls) {
        const postId = url.split("/").pop();
        if (alrdEmbedded.has(postId)) {
            continue;
        }

        const embedId = `${msgId}-twitter-${counter++}`;
        embedHtmls += `
            <div class="${embedSpacing} lg:w-[350px] mx-auto" id="${embedId}"></div>
        `;
        alrdEmbedded.add(url);
        twitterPostIds.push({
            id: postId,
            embedId: embedId,
        });
    }
    return [embedHtmls, twitterPostIds];
}

const youtubeUrlRegex = /https?:\/\/(?:www\.|m\.)?(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|shorts\/))([\w-]{11})(?:[^\s]*&t=([\dhms]{1,9}))?/g;
const ytTimeMap = {
    "h": 3600,
    "m": 60,
    "s": 1
}

function parseYoutubeHtml(
    videoId,
    time,
) {
    let timeMultipler;
    if (time) {
        timeMultipler = ytTimeMap[time[time.length - 1]];
    }
    return `
        <div class="${embedSpacing}">
            <lite-youtube 
                videoid="${videoId}" 
                ${time ? 'videoStartAt=' + (parseInt(time) * timeMultipler) : ''}
            >
            </lite-youtube>
        </div>
    `;
}
function getYoutubeUrlEmbeds(text, matchOneOnly = false) {
    // Find all YouTube URLs in the text
    if (matchOneOnly) {
        const match = youtubeUrlRegex.exec(text);
        if (match !== null) {
            const videoId = match[1];
            const time = match[2];
            return parseYoutubeHtml(videoId, time);
        }
    }

    let embedHtmls = "";
    let match;
    let alrdEmbedded = new Set();
    while ((match = youtubeUrlRegex.exec(text)) !== null) {
        const videoId = match[1];
        if (alrdEmbedded.has(videoId)) {
            continue;
        }

        const time = match[2];
        embedHtmls += parseYoutubeHtml(videoId, time);
        alrdEmbedded.add(videoId);
    }

    return embedHtmls;
}

const spotifyUrlRegex = /https?:\/\/(?:www\.)?open\.spotify\.com\/(track|playlist|artist|album)\/([a-zA-Z0-9]+)/g;
const spotifyHeightMap = {
    "track": 152,
    "album": 380,
    "playlist": 380,
    "artist": 380,
}

function getSpotifyUrlEmbeds(text) {
    let embedHtmls = "";
    let match;
    let alrdEmbedded = new Set();

    // Find all Spotify URLs in the text
    spotifyUrls = text.match(spotifyUrlRegex);
    if (!spotifyUrls) {
        return embedHtmls;
    }

    for (const url of spotifyUrls) {
        const splittedUrl = url.split("/");
        const id = splittedUrl.pop();
        if (alrdEmbedded.has(id)) {
            continue;
        }

        const type = splittedUrl.pop();
        embedHtmls += `
            <div class="${embedSpacing}">
                <iframe 
                    style="border-radius:12px"
                    src="https://open.spotify.com/embed/${type}/${id}?utm_source=generator"
                    width="100%" height="${spotifyHeightMap[type]}"
                    frameBorder="0" 
                    allowfullscreen="" 
                    allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" 
                    loading="lazy"
                >
                </iframe>
            </div>
        `;
        alrdEmbedded.add(id);
    }

    return embedHtmls;
}

const soundcloudUrlRegex = /(https?:\/\/(?:www\.)?soundcloud\.com\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+)/g;
function getSoundcloudUrlEmbeds(text) {
    let embedHtmls = "";
    let alrdEmbedded = new Set();

    // Find all SoundCloud URLs in the text
    matched = text.match(soundcloudUrlRegex);
    if (!matched) {
        return embedHtmls;
    }
    for (const url of matched) {
        if (alrdEmbedded.has(url)) {
            continue;
        }

        embedHtmls += `
            <div class="${embedSpacing}">
                <iframe width="100%" height="200px" scrolling="no" frameborder="no" allow="autoplay"
                    src="https://w.soundcloud.com/player/?url=${url}&color=%23ff5500&auto_play=false&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true&visual=true">
                </iframe>
            </div>
        `;
        alrdEmbedded.add(url);
    }

    return embedHtmls;
}

function getFileEmbeds(fileArr, isSender) {
    if (!fileArr) {
        return {
            html: [], 
            img: [], 
            plyrJs: [],
        };
    }

    let embedHtmls = "";
    const imageViewIds = [];
    const plyrJsIds = [];
    for (const fileObj of fileArr) {
        if (fileObj.type.startsWith("image") && !fileObj.treat_image_as_file) {
            const imageViewId = `imageView#${fileObj.blob_id}`;
            embedHtmls += `
                <button 
                    class="block w-full ${embedSpacing} aspect-video relative flex flex-shrink-0 max-w-xs lg:max-w-md" 
                    id="${imageViewId}"
                >
                    <img class="${getBlurFlag(fileObj) ? 'blur-md' : ''} absolute shadow-md w-full h-full rounded-lg object-contain bg-black" src="${fileObj.url}?compress=true" alt="${fileObj.filename}">
                </button>
            `;
            imageViewIds.push({
                elementId: imageViewId,
                url: fileObj.url,
            });
        } else if (fileObj.type.startsWith("video")) {
            const videoPlyrjsId = `plyr_${fileObj.blob_id}`;
            embedHtmls += `
                <div class="${embedSpacing}">
                    <video id="${videoPlyrjsId}" playsinline controls class="aspect-video">
                        <source src="${fileObj.url}" type="${fileObj.type}" />
                        <!-- Fallback for browsers that don't support the video element -->
                        <a href="${fileObj.url}" download>Download</a>
                    </video>
                </div>
            `;
            plyrJsIds.push({
                elementId: videoPlyrjsId,
                url: fileObj.url,
            });
        } else if (fileObj.type.startsWith("audio")) {
            const audioPlyrjsId = `plyr_${fileObj.blob_id}`;
            embedHtmls += `
                <div class="${embedSpacing}">
                    <audio id="${audioPlyrjsId}" controls>
                        <source src="${fileObj.url}" type="${fileObj.type}" />
                        <!-- Fallback for browsers that don't support the audio element -->
                        <a href="${fileObj.url}" download>Download</a>
                    </audio>
                </div>
            `;
            plyrJsIds.push({
                elementId: audioPlyrjsId,
                url: fileObj.url,
            });
        } else {
            if (!isSender) {
                embedHtmls += `
                    <div class="flex items-center ${embedSpacing}">
                        <i class="fas fa-file mx-2 my-auto"></i> 
                        <span class="break-all">${fileObj.filename}</span>
                        <a href="${fileObj.url}" target="_blank" class="mr-4 flex text-main-50 hover:text-main-700 hover:underline">
                            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                            </svg>
                            ${getReadableFileSize(fileObj.file_size)}
                        </a>
                    </div>
                `;
            } else {
                embedHtmls += `
                    <div class="flex items-center ${embedSpacing}">
                        <i class="fas fa-file mx-2 my-auto"></i> 
                        <span class="break-all">${fileObj.filename}</span>
                        <a href="${fileObj.url}" target="_blank" class="ml-4 flex text-white hover:text-gray-400 hover:underline">
                            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                            </svg>
                            ${getReadableFileSize(fileObj.file_size)}
                        </a>
                    </div>
                `;
            }
        }
    }
    return {
        html: embedHtmls, 
        img: imageViewIds, 
        plyrJs: plyrJsIds,
    };
}

function wrapUrlsInAnchorTags(str) {
    const urlRegex = /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g;
    return str.replace(urlRegex, (url) => {
        return `<a href="/redirect?url=${url}" target="_blank" class="underline">${url}</a>`;
    });
}

const plyrJsControls = [
    "play-large", // The large play button in the center
    //"restart", // Restart playback
    // "rewind", // Rewind by the seek time (default 10 seconds)
    "play", // Play/pause playback
    // "fast-forward", // Fast forward by the seek time (default 10 seconds)
    "progress", // The progress bar and scrubber for playback and buffering
    "current-time", // The current time of playback
    "duration", // The full duration of the media
    "mute", // Toggle mute
    "volume", // Volume control
    "captions", // Toggle captions
    "settings", // Settings menu
    "pip", // Picture-in-picture (currently Safari only)
    "airplay", // Airplay (currently Safari only)
    "download", // Show a download button with a link to either the current source or a custom URL you specify in your options
    "fullscreen" // Toggle fullscreen
];
const plyrJsOptionsWithoutDownload = plyrJsControls.filter((control) => control !== "download");

function formatPlyrJs(plyrArr, allowDownload = false) {
    if (!plyrArr) {
        return;
    }

    for (const plyrJsObj of plyrArr) {
        new Plyr(`#${plyrJsObj.elementId}`, {
            controls: 
                allowDownload ? plyrJsControls : plyrJsOptionsWithoutDownload,
            urls: {
                download: plyrJsObj.url,
            },
        });
    }
}

function getEmbedsForChatMsg(msgId, text, fileArr, isSender) {
    let embedHtmls = "";
    const fileEmbeds = getFileEmbeds(fileArr, isSender);
    embedHtmls += fileEmbeds.html;

    const twitterPostEmbedsRes = getTwitterPostEmbeds(
        msgId,
        text,
    );
    embedHtmls += twitterPostEmbedsRes[0];
    embedHtmls += getYoutubeUrlEmbeds(text);
    embedHtmls += getSpotifyUrlEmbeds(text);
    embedHtmls += getSoundcloudUrlEmbeds(text);
    return [embedHtmls, fileEmbeds, twitterPostEmbedsRes[1]];
}