import { createPopup } from "@picmo/popup-picker";
import { SHA3 } from "sha3";
import { Buffer } from "buffer";
const crypto = require("crypto");

window.arrayBufferToBuffer = (ab) => {
    // from https://stackoverflow.com/questions/8609289/convert-a-binary-nodejs-buffer-to-javascript-arraybuffer
    const buf = Buffer.alloc(ab.byteLength);
    const view = new Uint8Array(ab);
    for (let i = 0; i < buf.length; ++i) {
        buf[i] = view[i];
    }
    return buf;
};
window.DOMPurify = require("dompurify");
window.SHA3 = SHA3;
window.createPopup  = createPopup;
window.md5hash = (data, encoding = "hex") => {
    return crypto.createHash("md5").
        update(data).
        digest(encoding);
}
window.base64Encode = (data) => {
    return Buffer.from(data).toString("base64");
}