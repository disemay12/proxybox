#pragma once
// A freshly loaded private hive has no shell-folder mapping, so SHGetFolderPath
// (Chromium appData, Electron userData, MSI/NSIS helpers) falls back to the real
// %USERPROFILE% and every copy shares one profile. Seed the mapping first.

#include <windows.h>
#include <string>

namespace pbsandbox {

inline std::wstring ParentOf(const std::wstring& p)
{
    size_t i = p.find_last_of(L"\\/");
    return i == std::wstring::npos ? p : p.substr(0, i);
}

inline void EnsureDir(const std::wstring& p)
{
    if (!p.empty()) CreateDirectoryW(p.c_str(), nullptr);
}

inline bool SetString(HKEY root, const wchar_t* key, const wchar_t* name,
                      const std::wstring& value, DWORD type)
{
    HKEY k = nullptr;
    if (RegCreateKeyExW(root, key, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS)
        return false;
    LONG rc = RegSetValueExW(k, name, 0, type,
                             reinterpret_cast<const BYTE*>(value.c_str()),
                             (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return rc == ERROR_SUCCESS;
}

inline std::wstring Env(const wchar_t* name)
{
    wchar_t buf[32768];
    DWORD n = GetEnvironmentVariableW(name, buf, 32768);
    return (n > 0 && n < 32768) ? std::wstring(buf, n) : std::wstring();
}

inline void SeedShellFolders(HKEY hive)
{
    std::wstring appdata = Env(L"APPDATA");
    if (appdata.empty()) return;
    std::wstring local = Env(L"LOCALAPPDATA");
    std::wstring root = ParentOf(appdata);

    std::wstring desktop = root + L"\\Desktop";
    std::wstring personal = root + L"\\Documents";
    std::wstring pictures = root + L"\\Pictures";
    std::wstring music = root + L"\\Music";
    std::wstring videos = root + L"\\Videos";
    std::wstring downloads = root + L"\\Downloads";
    for (auto& d : {root, appdata, local, desktop, personal, pictures, music, videos, downloads})
        EnsureDir(d);

    struct Entry { const wchar_t* name; std::wstring path; };
    Entry entries[] = {
        {L"AppData", appdata},
        {L"Local AppData", local},
        {L"Desktop", desktop},
        {L"Personal", personal},
        {L"My Pictures", pictures},
        {L"My Music", music},
        {L"My Video", videos},
        {L"Downloads", downloads},
        {L"{374DE290-123F-4565-9164-39C4925E467B}", downloads},
    };
    const wchar_t* user = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
    const wchar_t* shell = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
    for (auto& e : entries) {
        SetString(hive, user, e.name, e.path, REG_EXPAND_SZ);
        SetString(hive, shell, e.name, e.path, REG_SZ);
    }

    std::wstring temp = Env(L"TEMP");
    if (!temp.empty()) {
        SetString(hive, L"Environment", L"TEMP", temp, REG_SZ);
        SetString(hive, L"Environment", L"TMP", temp, REG_SZ);
    }
}

// Loads the hive file, writes the mapping and unloads it again so the target
// process sees the values as soon as it overrides HKEY_CURRENT_USER.
inline bool SeedHiveFile(const wchar_t* path)
{
    HKEY hive = nullptr;
    if (RegLoadAppKeyW(path, &hive, KEY_ALL_ACCESS, 0, 0) != ERROR_SUCCESS) return false;
    SeedShellFolders(hive);
    RegCloseKey(hive);
    return true;
}

} // namespace pbsandbox
