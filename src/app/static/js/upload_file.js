function SHA3Hash(data) {
    const hash = new SHA3(256);
    return hash.update(data).digest("hex");
}

const filenameMetadata = "filename";
function removeDuplicateFilename(files) {
    const filenameSet = new Set();
    let i = 0;
    for (const file of files) {
        let filename = file.filename;
        if (filenameSet.has(filename)) {
            filename = `${++i}_${filename}`;
            file.setMetadata(filenameMetadata, filename)
        } else {
            file.setMetadata(filenameMetadata, filename)
        }
        filenameSet.add(filename);
    }
}

async function fetchUploadId(url, authorId, numberOfFiles, textMsg, uploadPurpose, extraData) {
    let reqBody = {
        author: authorId,
        text: textMsg,
        purpose: uploadPurpose,
        number_of_files: numberOfFiles,
    };
    if (textMsg && textMsg.length > 0) {
        reqBody = { ...reqBody, ...{ 
            md5_checksum: md5hash(textMsg),
            crc32c_checksum: CRC32C.str(textMsg) >>> 0,
        } };
    }
    if (extraData) {
        reqBody = { ...reqBody, ...extraData };
    }

    try {
        const uploadIdResponse = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCSRFToken(),
            },
            body: JSON.stringify(reqBody)
        });

        const data = await uploadIdResponse.json();
        if (uploadIdResponse.status !== 200) {
            throw new Error(data.message);
        }
        return data.upload_token;
    } catch (e) {
        console.error(e);
        throw new Error(e.message || "Error fetching upload token.");
    }
}

async function uploadChunks (url, file, metadata, chunkSize, formDataFunction, uploadToken, progressFunc) {
    // Split the file into chunks and send them to the server
    const filename = metadata.filename || file.name;
    if (filename == undefined) {
        throw new Error("Filename is undefined.");
    }
    const fileSize = file.size;
    const mimetype = file.type;
    const fileBuffer = arrayBufferToBuffer(await file.arrayBuffer());

    // calculate the MD5 checksum and convert it to base64
    const fileMd5Checksum = md5hash(fileBuffer, "base64");

    // Calculate the CRC32C checksum and convert it to base64
    let fileCrc32cChecksum = CRC32C.buf(fileBuffer) >>> 0;
    fileCrc32cChecksum = new Uint8Array([
        fileCrc32cChecksum >>> 24,
        fileCrc32cChecksum >>> 16,
        fileCrc32cChecksum >>> 8,
        fileCrc32cChecksum,
    ]);
    fileCrc32cChecksum = base64Encode(fileCrc32cChecksum);

    let currentChunk = 1;
    let start = 0;
    while (start < fileSize) {
        // Send the current chunk
        const end = start + chunkSize >= fileSize ? fileSize : start + chunkSize;
        const chunk = file.slice(start, end);
        const formData = formDataFunction();

        // hash the chunk
        const chunkHash = SHA3Hash(arrayBufferToBuffer(await chunk.arrayBuffer()));

        // Append the data to the FormData object
        formData.append("chunk", chunk);
        formData.append("chunk_index", currentChunk);
        formData.append("chunk_hash", chunkHash);
        formData.append("file_md5_checksum", fileMd5Checksum);
        formData.append("file_crc32c_checksum", fileCrc32cChecksum);
        formData.append("upload_token", uploadToken);
        formData.append("filename", filename);
        formData.append("mimetype", mimetype);

        let errorMsg;
        const xhr = new XMLHttpRequest();
        try {
            xhr.open("POST", url, true);
            xhr.setRequestHeader("Content-Range", `bytes ${start}-${end - 1}/${fileSize}`);
            xhr.setRequestHeader("X-CSRF-Token", getCSRFToken());
            xhr.onreadystatechange = () => {
                try {
                    let chunkUploadResponseData;
                    if (xhr.responseText) {
                        chunkUploadResponseData = JSON.parse(xhr.responseText);
                    }
                    if (xhr.status !== 200) {
                        errorMsg = chunkUploadResponseData.message;
                        throw new Error(errorMsg);
                    }
                } catch (e) {
                    console.error(e);
                    if (errorMsg === undefined) {
                        errorMsg = "Error uploading file.";
                    }
                }
            }
            xhr.upload.onprogress = (e) => {
                progressFunc(e.lengthComputable, start + e.loaded, fileSize);
            };

            // send and wait till the response is received
            await new Promise((resolve, reject) => {
                xhr.onload = () => resolve();
                xhr.onerror = () => reject();
                xhr.send(formData);
            });
            if (errorMsg !== undefined) {
                throw new Error(errorMsg);
            }
        } catch (e) {
            console.error(e);
            xhr.abort();
            throw new Error(errorMsg);
        }

        start += chunkSize;
        currentChunk++;
    }
}