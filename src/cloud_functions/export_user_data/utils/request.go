package utils

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// send the request to the target URL and retries if the request was not successful
func sendRequest(reqUrl string, req *http.Request, timeout int, checkStatus, disableCompression bool) (*http.Response, error) {
	var err error
	var res *http.Response

	transport := &http.Transport{
		DisableCompression: disableCompression,
	}
	client := &http.Client{
		Transport: transport,
	}
	client.Timeout = time.Duration(timeout) * time.Second
	for i := 1; i <= RETRY_COUNTER; i++ {
		res, err = client.Do(req)
		if err == nil {
			if !checkStatus {
				return res, nil
			} else if res.StatusCode == 200 {
				return res, nil
			}
		}
		time.Sleep(GetRandomDelay())
	}
	err = fmt.Errorf("request to %s failed after %d retries", reqUrl, RETRY_COUNTER)
	log.Println(err)
	return nil, err
}

// add headers to the request
func AddHeaders(headers map[string]string, req *http.Request) {
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Add(
			"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
		)
	}
}

// add cookies to the request
func AddCookies(reqUrl string, cookies []http.Cookie, req *http.Request) {
	for _, cookie := range cookies {
		if strings.Contains(reqUrl, cookie.Domain) {
			req.AddCookie(&cookie)
		}
	}
}

// add params to the request
func AddParams(params map[string]string, req *http.Request) {
	if len(params) > 0 {
		query := req.URL.Query()
		for key, value := range params {
			query.Add(key, value)
		}
		req.URL.RawQuery = query.Encode()
	}
}

// CallRequest is used to make a request to a URL and return the response
//
// If the request fails, it will retry the request again up 
// to the defined max retries in the constants.go in utils package
func CallRequest(
	method, reqUrl string, timeout int, cookies []http.Cookie, 
	additionalHeaders, params map[string]string, checkStatus bool,
) (*http.Response, error) {
	req, err := http.NewRequest(method, reqUrl, nil)
	if err != nil {
		return nil, err
	}

	AddCookies(reqUrl, cookies, req)
	AddHeaders(additionalHeaders, req)
	AddParams(params, req)
	return sendRequest(reqUrl, req, timeout, checkStatus, false)
}

// Sends a request with the given data
func CallRequestWithData(
	reqUrl, method string, timeout int, cookies []http.Cookie, 
	data, additionalHeaders, params map[string]string, checkStatus bool,
) (*http.Response, error) {
	form := url.Values{}
	for key, value := range data {
		form.Add(key, value)
	}
	if len(data) > 0 {
		additionalHeaders["Content-Type"] = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequest(method, reqUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	AddCookies(reqUrl, cookies, req)
	AddHeaders(additionalHeaders, req)
	AddParams(params, req)
	return sendRequest(reqUrl, req, timeout, checkStatus, false)
}

// Sends a request to the given URL but disables golang's HTTP client compression
//
// Useful for calling a HEAD request to obtain the actual uncompressed file's file size
func CallRequestNoCompression(
	method, reqUrl string, timeout int, cookies []http.Cookie, 
	additionalHeaders, params map[string]string, checkStatus bool,
) (*http.Response, error) {
	req, err := http.NewRequest(method, reqUrl, nil)
	if err != nil {
		return nil, err
	}

	AddCookies(reqUrl, cookies, req)
	AddHeaders(additionalHeaders, req)
	AddParams(params, req)
	return sendRequest(reqUrl, req, timeout, checkStatus, true)
}

// DownloadURL is used to download a file from a URL
//
// Note: If the file already exists, the download process will be skipped
func DownloadURL(
	fileURL, filePath string, cookies []http.Cookie, 
	headers, params map[string]string, overwriteExistingFiles bool,
) error {
	downloadTimeout := 25 * 60 // 25 minutes for large files
	res, err := CallRequest("GET", fileURL, downloadTimeout, cookies, headers, params, true)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// check if filepath already have a filename attached
	if filepath.Ext(filePath) == "" {
		os.MkdirAll(filePath, 0755)
		filename, err := url.PathUnescape(res.Request.URL.String())
		if err != nil {
			panic(err)
		}
		// GetLastPartOfURL
		filename = filepath.Base(filename)
		filenameWithoutExt := RemoveExtFromFilename(filename)
		filePath = filepath.Join(filePath, filenameWithoutExt + strings.ToLower(filepath.Ext(filename)))
	} else {
		filePathDir := filepath.Dir(filePath)
		os.MkdirAll(filePathDir, 0755)
		filePathWithoutExt := RemoveExtFromFilename(filePath)
		filePath = filePathWithoutExt + strings.ToLower(filepath.Ext(filePath))
	}

	file, err := os.Create(filePath) // create the file
	if err != nil {
		panic(err)
	}

	// write the body to file
	// https://stackoverflow.com/a/11693049/16377492
	_, err = io.Copy(file, res.Body)
	if err != nil {
		file.Close()
		os.Remove(filePath)
		errorMsg := fmt.Sprintf("failed to download %s due to %v", fileURL, err)
		log.Println(errorMsg)
		return nil
	}
	file.Close()
	return nil
}

// DownloadURLsParallel is used to download multiple files from URLs in parallel
//
// Note: If the file already exists, the download process will be skipped
func DownloadURLsParallel(
	urls []map[string]string, maxConcurrency int, cookies []http.Cookie, 
	headers, params map[string]string, overwriteExistingFiles bool,
) {
	if len(urls) == 0 {
		return
	}
	if len(urls) < maxConcurrency {
		maxConcurrency = len(urls)
	}

	var wg sync.WaitGroup
	queue := make(chan struct{}, maxConcurrency)
	for _, url := range urls {
		wg.Add(1)
		queue <- struct{}{}
		go func(fileUrl, filePath string) {
			defer wg.Done()
			DownloadURL(fileUrl, filePath, cookies, headers, params, overwriteExistingFiles)
			<-queue
		}(url["url"], url["filepath"])
	}
	close(queue)
	wg.Wait()
}