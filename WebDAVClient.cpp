#include "WebDAVClient.h"
#include <regex>
#include <wincrypt.h>
#include <wincred.h>
#include <sstream>
#include <iomanip>
#include "pugixml.hpp"

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Credui.lib")

std::unordered_map<std::wstring, std::pair<std::wstring, std::wstring>> WebDAVClient::s_credCache;
std::mutex WebDAVClient::s_credMutex;
std::unordered_map<std::wstring, std::shared_ptr<std::mutex>> WebDAVClient::s_hostAuthLocks;
std::mutex WebDAVClient::s_hostAuthLocksMutex;
HINTERNET WebDAVClient::s_hGlobalSession = NULL;

std::unordered_map<std::wstring, WebDAVClient::StatCacheEntry> WebDAVClient::s_statCache;
std::mutex WebDAVClient::s_statCacheMutex;

std::wstring WebDAVClient::GetCacheKey(const WebDAVUrl& urlInfo) {
    std::wstring p = urlInfo.path;
    if (p.length() > 1 && p.back() == L'/') p.pop_back();
    return urlInfo.host + L":" + std::to_wstring(urlInfo.port) + p;
}

std::wstring WebDAVClient::GetChildCacheKey(const WebDAVUrl& urlInfo, const std::wstring& childName) {
    std::wstring p = urlInfo.path;
    if (!p.empty() && p.back() != L'/') p += L'/';
    p += childName;
    if (p.length() > 1 && p.back() == L'/') p.pop_back();
    return urlInfo.host + L":" + std::to_wstring(urlInfo.port) + p;
}

void WebDAVClient::Init() {
    if (!s_hGlobalSession) {
        s_hGlobalSession = WinHttpOpen(L"DOpusWebDAV/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        DWORD dwFlags = WINHTTP_PROTOCOL_FLAG_HTTP2;
        WinHttpSetOption(s_hGlobalSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &dwFlags, sizeof(dwFlags));
    }
}

void WebDAVClient::Cleanup() {
    if (s_hGlobalSession) { WinHttpCloseHandle(s_hGlobalSession); s_hGlobalSession = NULL; }
}

bool WebDAVClient::ParseUrl(const std::wstring& url, WebDAVUrl& outUrl) {
    std::wstring cleanUrl = url;
    for (auto& c : cleanUrl) { if (c == L'\\') c = L'/'; }
    std::wregex urlRegex(L"^(davs?)://(?:([^:@]+)(?::([^@]+))?@)?([^:/]+)(?::(\\d+))?(?:/(.*))?$", std::regex::icase);
    std::wsmatch match;
    if (std::regex_match(cleanUrl, match, urlRegex)) {
        outUrl.scheme = match[1].str(); outUrl.username = match[2].str(); outUrl.password = match[3].str();
        outUrl.host = match[4].str();
        if (match[5].matched) { outUrl.port = std::stoi(match[5].str()); } 
        else { outUrl.port = (_wcsicmp(outUrl.scheme.c_str(), L"davs") == 0) ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT; }
        outUrl.path = L"/" + match[6].str();
        return true;
    }
    return false;
}

void WebDAVClient::PrepareAuth(HWND hwndParent, WebDAVUrl& urlInfo) {
    std::wstring cacheKey = urlInfo.host + L":" + std::to_wstring(urlInfo.port);
    std::shared_ptr<std::mutex> hostLock;
    
    {
        std::lock_guard<std::mutex> lock(s_hostAuthLocksMutex);
        for (auto it = s_hostAuthLocks.begin(); it != s_hostAuthLocks.end(); ) {
            if (it->second.use_count() == 1) {
                it = s_hostAuthLocks.erase(it);
            } else {
                ++it;
            }
        }
        if (s_hostAuthLocks.find(cacheKey) == s_hostAuthLocks.end()) {
            s_hostAuthLocks[cacheKey] = std::make_shared<std::mutex>();
        }
        hostLock = s_hostAuthLocks[cacheKey];
    }

    std::lock_guard<std::mutex> lock(*hostLock); 
    {
        std::lock_guard<std::mutex> cacheLock(s_credMutex);
        if (urlInfo.username.empty() && s_credCache.count(cacheKey)) {
            urlInfo.username = s_credCache[cacheKey].first; urlInfo.password = s_credCache[cacheKey].second; return; 
        }
    }

    if (urlInfo.username.empty() || urlInfo.password.empty()) {
        if (PromptCredentials(hwndParent, cacheKey, urlInfo.username, urlInfo.password)) {
            std::lock_guard<std::mutex> cacheLock(s_credMutex);
            s_credCache[cacheKey] = {urlInfo.username, urlInfo.password};
        }
    }
}

std::wstring WebDAVClient::UrlEncodePath(const std::wstring& path) {
    std::string utf8Path = WideToUtf8(path); std::ostringstream escaped; escaped.fill('0'); escaped << std::hex;
    for (char c : utf8Path) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') escaped << c;
        else escaped << std::uppercase << '%' << std::setw(2) << int((unsigned char)c) << std::nouppercase;
    }
    return Utf8ToWide(escaped.str());
}

std::string WebDAVClient::Base64Encode(const std::wstring& user, const std::wstring& pass) {
    std::string credentials = WideToUtf8(user) + ":" + WideToUtf8(pass); DWORD len = 0;
    if (!CryptBinaryToStringA((const BYTE*)credentials.data(), (DWORD)credentials.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len) || len == 0) return "";
    std::string result(len, '\0');
    CryptBinaryToStringA((const BYTE*)credentials.data(), (DWORD)credentials.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &len);
    if (!result.empty() && result.back() == '\0') result.pop_back(); 
    return result;
}

bool WebDAVClient::PromptCredentials(HWND hwndParent, const std::wstring& targetName, std::wstring& outUser, std::wstring& outPass) {
    CREDUI_INFOW defaultInfo = {0}; defaultInfo.cbSize = sizeof(CREDUI_INFOW); defaultInfo.hwndParent = hwndParent;
    WCHAR userName[CREDUI_MAX_USERNAME_LENGTH + 1] = {0}; WCHAR password[CREDUI_MAX_PASSWORD_LENGTH + 1] = {0}; BOOL save = FALSE;
    DWORD res = CredUIPromptForCredentialsW(&defaultInfo, targetName.c_str(), NULL, 0, userName, CREDUI_MAX_USERNAME_LENGTH, password, CREDUI_MAX_PASSWORD_LENGTH, &save, CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST);
    if (res == ERROR_SUCCESS) { outUser = userName; outPass = password; SecureZeroMemory(password, sizeof(password)); return true; }
    return false;
}

std::vector<WebDAVFileInfo> WebDAVClient::ListDirectory(const WebDAVUrl& urlInfo) {
    std::vector<WebDAVFileInfo> results;
    if (!s_hGlobalSession) return results;

    std::wstring reqPath = urlInfo.path;
    if (reqPath.empty() || reqPath.back() != L'/') reqPath += L'/';

    int retryCount = 0;
    while (retryCount <= 3) { 
        HINTERNET hConnect = WinHttpConnect(s_hGlobalSession, urlInfo.host.c_str(), urlInfo.port, 0);
        if (!hConnect) break;

        DWORD flags = (urlInfo.port == INTERNET_DEFAULT_HTTPS_PORT || _wcsicmp(urlInfo.scheme.c_str(), L"davs") == 0) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"PROPFIND", UrlEncodePath(reqPath).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

        bool requestSuccess = false;
        bool shouldRetry = false;
        DWORD lastErr = ERROR_SUCCESS;

        if (hRequest) {
            std::wstring headers = L"Depth: 1\r\n";
            if (!urlInfo.username.empty()) headers += L"Authorization: Basic " + Utf8ToWide(Base64Encode(urlInfo.username, urlInfo.password)) + L"\r\n";
            headers += L"Content-Type: text/xml; charset=\"utf-8\"\r\n";

            std::string reqBody = "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:getlastmodified/><D:getcontentlength/><D:resourcetype/></D:prop></D:propfind>";

            if (WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1, (LPVOID)reqBody.c_str(), (DWORD)reqBody.length(), (DWORD)reqBody.length(), 0)) {
                if (WinHttpReceiveResponse(hRequest, NULL)) {
                    DWORD statusCode = 0; DWORD sz = sizeof(statusCode);
                    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &sz, WINHTTP_NO_HEADER_INDEX);

                    if (statusCode == 502 || statusCode == 503 || statusCode == 504 || statusCode == 500) {
                        shouldRetry = true;
                    } else if (statusCode >= 400 && statusCode < 600) {
                        if (statusCode == 401 || statusCode == 403) lastErr = ERROR_ACCESS_DENIED;
                        else lastErr = ERROR_PATH_NOT_FOUND;
                    } else {
                        requestSuccess = true;
                        std::string xmlResponse; DWORD dwSize = 0, dwDownloaded = 0;
                        xmlResponse.reserve(32768); 
                        std::vector<char> buffer(8192, 0);
                        do {
                            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
                            if (dwSize > buffer.size() - 1) {
                                buffer.resize(dwSize + 1, 0);
                            }
                            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) break;
                            xmlResponse.append(buffer.data(), dwDownloaded);
                        } while (dwSize > 0);

                        pugi::xml_document doc;
                        if (doc.load_string(xmlResponse.c_str())) {
                            auto get_child = [](pugi::xml_node node, const char* name) -> pugi::xml_node {
                                for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
                                    std::string n = child.name(); size_t pos = n.find(':');
                                    if ((pos != std::string::npos ? n.substr(pos + 1) : n) == name) return child;
                                } return pugi::xml_node();
                            };

                            auto get_child_value = [&](pugi::xml_node node, const char* name) -> std::string {
                                pugi::xml_node child = get_child(node, name); return child ? child.text().get() : "";
                            };

                            pugi::xml_node multistatus = get_child(doc, "multistatus");
                            for (pugi::xml_node responseNode = multistatus.first_child(); responseNode; responseNode = responseNode.next_sibling()) {
                                std::string rName = responseNode.name(); size_t rPos = rName.find(':');
                                if ((rPos != std::string::npos ? rName.substr(rPos + 1) : rName) != "response") continue;

                                WebDAVFileInfo info;
                                info.isDir = false; info.size = 0; FILETIME ftZero = {0}; info.lastModified = ftZero;

                                std::string rawHref = get_child_value(responseNode, "href");
                                std::string decodedHref = UrlDecode(rawHref); 
                                
                                bool isSelf = false;
                                std::string testHref = decodedHref;
                                if (testHref.length() > 1 && testHref.back() == '/') testHref.pop_back();
                                std::string decodedSelfPath = WideToUtf8(urlInfo.path);
                                if (decodedSelfPath.length() > 1 && decodedSelfPath.back() == '/') decodedSelfPath.pop_back();

                                if (testHref.length() >= decodedSelfPath.length() && 
                                    testHref.substr(testHref.length() - decodedSelfPath.length()) == decodedSelfPath) {
                                    isSelf = true;
                                }

                                std::string href = testHref;
                                size_t slashPos = href.find_last_of('/');
                                if (slashPos != std::string::npos) href = href.substr(slashPos + 1);
                                if (href.empty() && !isSelf) continue; 
                                info.name = Utf8ToWide(href);

                                pugi::xml_node propstat = get_child(responseNode, "propstat");
                                pugi::xml_node prop = get_child(propstat, "prop");
                                pugi::xml_node resType = get_child(prop, "resourcetype");
                                info.isDir = !get_child(resType, "collection").empty();
                                
                                std::string lenStr = get_child_value(prop, "getcontentlength");
                                try { info.size = lenStr.empty() ? 0 : std::stoull(lenStr); } catch (...) { info.size = 0; }
                                info.lastModified = ParseHttpTime(get_child_value(prop, "getlastmodified"));
                                
                                std::wstring cacheKey = isSelf ? GetCacheKey(urlInfo) : GetChildCacheKey(urlInfo, info.name);
                                {
                                    std::lock_guard<std::mutex> cacheLock(s_statCacheMutex);
                                    s_statCache[cacheKey] = { info, GetTickCount64() };
                                }

                                if (!isSelf) results.push_back(info);
                            }
                        }
                    }
                } else { shouldRetry = true; lastErr = GetLastError(); }
            } else { shouldRetry = true; lastErr = GetLastError(); }
            WinHttpCloseHandle(hRequest);
        } else { shouldRetry = true; lastErr = GetLastError(); }
        WinHttpCloseHandle(hConnect);

        if (requestSuccess) {
            SetLastError(ERROR_SUCCESS);
            return results;
        }

        if (shouldRetry && retryCount < 3) {
            retryCount++;
            Sleep(100); 
            continue;
        }

        SetLastError(lastErr != ERROR_SUCCESS ? lastErr : ERROR_BAD_NET_RESP);
        break;
    }
    return results;
}

bool WebDAVClient::Stat(const WebDAVUrl& urlInfo, WebDAVFileInfo& outInfo) {
    std::wstring cacheKey = GetCacheKey(urlInfo);
    ULONGLONG now = GetTickCount64();

    {
        std::lock_guard<std::mutex> lock(s_statCacheMutex);
        if (s_statCache.size() > 2000) {
            for (auto it = s_statCache.begin(); it != s_statCache.end(); ) {
                if (now - it->second.timestamp > 5000) {
                    it = s_statCache.erase(it);
                } else {
                    ++it;
                }
            }
        }
        auto it = s_statCache.find(cacheKey);
        if (it != s_statCache.end() && (now - it->second.timestamp <= 5000)) {
            outInfo = it->second.info;
            return true;
        }
    }

    if (!s_hGlobalSession) return false;
    HINTERNET hConnect = WinHttpConnect(s_hGlobalSession, urlInfo.host.c_str(), urlInfo.port, 0);
    if (!hConnect) return false;

    DWORD flags = (urlInfo.port == INTERNET_DEFAULT_HTTPS_PORT || _wcsicmp(urlInfo.scheme.c_str(), L"davs") == 0) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"PROPFIND", UrlEncodePath(urlInfo.path).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    bool success = false;
    if (hRequest) {
        std::wstring headers = L"Depth: 0\r\n";
        if (!urlInfo.username.empty()) headers += L"Authorization: Basic " + Utf8ToWide(Base64Encode(urlInfo.username, urlInfo.password)) + L"\r\n";
        headers += L"Content-Type: text/xml; charset=\"utf-8\"\r\n";

        std::string reqBody = "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:getlastmodified/><D:getcontentlength/><D:resourcetype/></D:prop></D:propfind>";
        if (WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1, (LPVOID)reqBody.c_str(), (DWORD)reqBody.length(), (DWORD)reqBody.length(), 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                std::string xmlResponse; DWORD dwSize = 0, dwDownloaded = 0;
                do {
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
                    std::vector<char> buffer(dwSize + 1, 0);
                    if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) break;
                    xmlResponse.append(buffer.data(), dwDownloaded);
                } while (dwSize > 0);

                pugi::xml_document doc;
                if (doc.load_string(xmlResponse.c_str())) {
                    auto get_child = [](pugi::xml_node node, const char* name) -> pugi::xml_node {
                        for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
                            std::string n = child.name(); size_t pos = n.find(':');
                            if ((pos != std::string::npos ? n.substr(pos + 1) : n) == name) return child;
                        } return pugi::xml_node();
                    };
                    pugi::xml_node prop = get_child(get_child(get_child(get_child(doc, "multistatus"), "response"), "propstat"), "prop");
                    if (prop) {
                        outInfo.isDir = !get_child(get_child(prop, "resourcetype"), "collection").empty();
                        std::string lenStr = get_child(prop, "getcontentlength") ? get_child(prop, "getcontentlength").text().get() : "";
                        try { outInfo.size = lenStr.empty() ? 0 : std::stoull(lenStr); } catch (...) { outInfo.size = 0; }
                        outInfo.lastModified = ParseHttpTime(get_child(prop, "getlastmodified") ? get_child(prop, "getlastmodified").text().get() : "");
                        success = true;
                        
                        std::lock_guard<std::mutex> lock(s_statCacheMutex);
                        s_statCache[cacheKey] = { outInfo, GetTickCount64() };
                    }
                }
            }
        }
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    return success;
}

std::wstring WebDAVClient::Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    if (size == 0) return L"";
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &result[0], size);
    return result;
}

std::string WebDAVClient::WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    if (size == 0) return "";
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &result[0], size, NULL, NULL);
    return result;
}

FILETIME WebDAVClient::ParseHttpTime(const std::string& timeStr) {
    FILETIME ft = {0}; SYSTEMTIME st = {0}; std::wstring wTime = Utf8ToWide(timeStr);
    if (!wTime.empty() && WinHttpTimeToSystemTime(wTime.c_str(), &st)) { SystemTimeToFileTime(&st, &ft); return ft; }
    int year, month, day, hour, min, sec;
    if (sscanf_s(timeStr.c_str(), "%d-%d-%dT%d:%d:%dZ", &year, &month, &day, &hour, &min, &sec) == 6) {
        st.wYear = year; st.wMonth = month; st.wDay = day; st.wHour = hour; st.wMinute = min; st.wSecond = sec;
        SystemTimeToFileTime(&st, &ft); return ft;
    }
    GetSystemTimeAsFileTime(&ft); return ft;
}

void WebDAVClient::InvalidateCache(const WebDAVUrl& urlInfo) {
    std::wstring cacheKey = GetCacheKey(urlInfo);
    std::lock_guard<std::mutex> lock(s_statCacheMutex);
    s_statCache.erase(cacheKey);
}

static bool SendSimpleRequest(const WebDAVUrl& urlInfo, const std::wstring& method) {
    if (!WebDAVClient::s_hGlobalSession) return false;
    HINTERNET hConnect = WinHttpConnect(WebDAVClient::s_hGlobalSession, urlInfo.host.c_str(), urlInfo.port, 0);
    if (!hConnect) return false;

    DWORD flags = (urlInfo.port == INTERNET_DEFAULT_HTTPS_PORT || _wcsicmp(urlInfo.scheme.c_str(), L"davs") == 0) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), WebDAVClient::UrlEncodePath(urlInfo.path).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    bool success = false;
    if (hRequest) {
        std::wstring headers = L"";
        if (!urlInfo.username.empty()) headers += L"Authorization: Basic " + WebDAVClient::Utf8ToWide(WebDAVClient::Base64Encode(urlInfo.username, urlInfo.password)) + L"\r\n";
        
        if (WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD statusCode = 0; DWORD size = sizeof(statusCode);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
                success = (statusCode >= 200 && statusCode < 300); 
            }
        }
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    if (success) WebDAVClient::InvalidateCache(urlInfo);
    return success;
}

bool WebDAVClient::Delete(const WebDAVUrl& urlInfo) { return SendSimpleRequest(urlInfo, L"DELETE"); }
bool WebDAVClient::MakeDir(const WebDAVUrl& urlInfo) { return SendSimpleRequest(urlInfo, L"MKCOL"); }

bool WebDAVClient::Move(const WebDAVUrl& srcUrl, const WebDAVUrl& destUrl) {
    if (!s_hGlobalSession) return false;
    HINTERNET hConnect = WinHttpConnect(s_hGlobalSession, srcUrl.host.c_str(), srcUrl.port, 0);
    if (!hConnect) return false;

    DWORD flags = (srcUrl.port == INTERNET_DEFAULT_HTTPS_PORT || _wcsicmp(srcUrl.scheme.c_str(), L"davs") == 0) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"MOVE", UrlEncodePath(srcUrl.path).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    bool success = false;
    if (hRequest) {
        std::wstring httpScheme = (_wcsicmp(destUrl.scheme.c_str(), L"davs") == 0) ? L"https" : L"http";
        std::wstring destPathStr = httpScheme + L"://" + destUrl.host;
        if (destUrl.port != 80 && destUrl.port != 443) destPathStr += L":" + std::to_wstring(destUrl.port);
        destPathStr += UrlEncodePath(destUrl.path);

        std::wstring headers = L"Destination: " + destPathStr + L"\r\n";
        if (!srcUrl.username.empty()) headers += L"Authorization: Basic " + Utf8ToWide(Base64Encode(srcUrl.username, srcUrl.password)) + L"\r\n";
        
        if (WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD statusCode = 0; DWORD size = sizeof(statusCode);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
                success = (statusCode == 201 || statusCode == 204); 
            }
        }
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    if (success) { InvalidateCache(srcUrl); InvalidateCache(destUrl); }
    return success;
}

WebDAVClient::FileStreamContext* WebDAVClient::BeginDownload(const WebDAVUrl& urlInfo) {
    FileStreamContext* ctx = new FileStreamContext{false, NULL, NULL, 0};
    ctx->hConnect = WinHttpConnect(s_hGlobalSession, urlInfo.host.c_str(), urlInfo.port, 0);
    if (!ctx->hConnect) { delete ctx; return NULL; }
    
    DWORD flags = (urlInfo.port == INTERNET_DEFAULT_HTTPS_PORT || _wcsicmp(urlInfo.scheme.c_str(), L"davs") == 0) ? WINHTTP_FLAG_SECURE : 0;
    ctx->hRequest = WinHttpOpenRequest(ctx->hConnect, L"GET", UrlEncodePath(urlInfo.path).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    std::wstring headers = L"";
    if (!urlInfo.username.empty()) headers += L"Authorization: Basic " + Utf8ToWide(Base64Encode(urlInfo.username, urlInfo.password)) + L"\r\n";
    
    if (WinHttpSendRequest(ctx->hRequest, headers.c_str(), -1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(ctx->hRequest, NULL)) {
        DWORD statusCode = 0; DWORD dwSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(ctx->hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
            if (statusCode >= 200 && statusCode < 300) {
                DWORD lenStrSize = 64; WCHAR lenStr[64] = {0};
                if (WinHttpQueryHeaders(ctx->hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lenStr, &lenStrSize, WINHTTP_NO_HEADER_INDEX)) {
                    try { ctx->fileSize = std::stoull(lenStr); } catch (...) { ctx->fileSize = 0; }
                }
                return ctx;
            }
        }
    }
    
    if (ctx->hRequest) WinHttpCloseHandle(ctx->hRequest);
    if (ctx->hConnect) WinHttpCloseHandle(ctx->hConnect);
    delete ctx; return NULL;
}

WebDAVClient::FileStreamContext* WebDAVClient::BeginUpload(const WebDAVUrl& urlInfo) {
    FileStreamContext* ctx = new FileStreamContext{true, NULL, NULL, 0};
    ctx->hConnect = WinHttpConnect(s_hGlobalSession, urlInfo.host.c_str(), urlInfo.port, 0);
    if (!ctx->hConnect) { delete ctx; return NULL; }
    
    DWORD flags = (urlInfo.port == INTERNET_DEFAULT_HTTPS_PORT || _wcsicmp(urlInfo.scheme.c_str(), L"davs") == 0) ? WINHTTP_FLAG_SECURE : 0;
    ctx->hRequest = WinHttpOpenRequest(ctx->hConnect, L"PUT", UrlEncodePath(urlInfo.path).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    std::wstring headers = L"Transfer-Encoding: chunked\r\n";
    if (!urlInfo.username.empty()) headers += L"Authorization: Basic " + Utf8ToWide(Base64Encode(urlInfo.username, urlInfo.password)) + L"\r\n";
    
    if (WinHttpSendRequest(ctx->hRequest, headers.c_str(), -1, WINHTTP_NO_REQUEST_DATA, 0, WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH, 0)) {
        return ctx;
    }
    
    if (ctx->hRequest) WinHttpCloseHandle(ctx->hRequest);
    if (ctx->hConnect) WinHttpCloseHandle(ctx->hConnect);
    delete ctx; return NULL;
}

std::string WebDAVClient::UrlDecode(const std::string& value) {
    std::string result;
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%' && i + 2 < value.length()) {
            unsigned int hex;
            if (sscanf_s(value.substr(i + 1, 2).c_str(), "%x", &hex) == 1) { result += static_cast<char>(hex); i += 2; } 
            else { result += value[i]; }
        } else if (value[i] == '+') { result += ' '; } 
        else { result += value[i]; }
    }
    return result;
}
