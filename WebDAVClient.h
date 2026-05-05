#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <winhttp.h>
#include <unordered_map>
#include <mutex>
#include <memory>

struct WebDAVUrl {
    std::wstring scheme;
    std::wstring username;
    std::wstring password;
    std::wstring host;
    int port;
    std::wstring path;
};

struct WebDAVFileInfo {
    std::wstring name;
    bool isDir;
    uint64_t size;
    FILETIME lastModified;
};

class WebDAVClient {
public:
    static void Init();
    static void Cleanup();
    static bool ParseUrl(const std::wstring& url, WebDAVUrl& outUrl);
    static std::string Base64Encode(const std::wstring& user, const std::wstring& pass);
    static bool PromptCredentials(HWND hwndParent, const std::wstring& targetName, std::wstring& outUser, std::wstring& outPass);
    
    static std::wstring Utf8ToWide(const std::string& str);
    static std::string WideToUtf8(const std::wstring& wstr);
    static std::string UrlDecode(const std::string& str);
    static std::wstring UrlEncodePath(const std::wstring& path);
    static FILETIME ParseHttpTime(const std::string& timeStr);
    
    struct FileStreamContext {
        bool isWrite;
        HINTERNET hConnect;
        HINTERNET hRequest;
        uint64_t fileSize;
    };

    static std::vector<WebDAVFileInfo> ListDirectory(const WebDAVUrl& urlInfo);
    static void PrepareAuth(HWND hwndParent, WebDAVUrl& urlInfo);
    
    static bool Stat(const WebDAVUrl& urlInfo, WebDAVFileInfo& outInfo);
    
    static bool Move(const WebDAVUrl& srcUrl, const WebDAVUrl& destUrl);
    static bool Delete(const WebDAVUrl& urlInfo);
    static bool MakeDir(const WebDAVUrl& urlInfo);

    static FileStreamContext* BeginDownload(const WebDAVUrl& urlInfo);
    static FileStreamContext* BeginUpload(const WebDAVUrl& urlInfo);

    static std::unordered_map<std::wstring, std::pair<std::wstring, std::wstring>> s_credCache;
    static std::mutex s_credMutex;
    static std::unordered_map<std::wstring, std::shared_ptr<std::mutex>> s_hostAuthLocks;
    static std::mutex s_hostAuthLocksMutex;
    static HINTERNET s_hGlobalSession;

    struct StatCacheEntry {
        WebDAVFileInfo info;
        ULONGLONG timestamp;
    };
    static std::unordered_map<std::wstring, StatCacheEntry> s_statCache;
    static std::mutex s_statCacheMutex;
    static std::wstring GetCacheKey(const WebDAVUrl& urlInfo);
    static std::wstring GetChildCacheKey(const WebDAVUrl& urlInfo, const std::wstring& childName);
    static void InvalidateCache(const WebDAVUrl& urlInfo);
};
