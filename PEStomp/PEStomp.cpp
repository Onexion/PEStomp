// PEStomp.cpp — modifies the TimeDateStamp field of a PE file.
// Build: cl /std:c++20 /EHsc /O2 /MT PEStomp.cpp /Fe:PEStomp.exe
//
// Usage:
//   PEStomp.exe <file.exe> --year <start> <end>   random year in range
//   PEStomp.exe <file.exe> --random               random 1990-2030
//   PEStomp.exe <file.exe> --zero                 set to zero
//   PEStomp.exe <file.exe> --now                  current timestamp
//   PEStomp.exe <file.exe> --set <hex>            custom value

#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <iostream>
#include <ctime>

// Reads the entire file into a byte buffer.
static bool ReadFileBytes(const std::string& path, std::vector<uint8_t>& out) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) { CloseHandle(h); return false; }

    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(h);
    return ok && read == out.size();
}

// Writes the buffer back to the file, overwriting it completely.
static bool WriteFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(h);
    return ok && written == data.size();
}

// Locates the offset of the TimeDateStamp field inside IMAGE_FILE_HEADER.
// Layout:
//   DOS header (0x00) -> e_lfanew at 0x3C -> PE signature (4 bytes)
//   -> IMAGE_FILE_HEADER (20 bytes):
//        Machine              (2 bytes)  +0
//        NumberOfSections     (2 bytes)  +2
//        TimeDateStamp        (4 bytes)  +4   <- target field
//        PointerToSymbolTable (4 bytes)  +8
//        NumberOfSymbols      (4 bytes)  +12
//        SizeOfOptionalHeader (2 bytes)  +16
//        Characteristics      (2 bytes)  +18
static bool FindTimeDateStampOffset(const std::vector<uint8_t>& data, size_t& outOffset) {
    if (data.size() < 0x40) return false;

    // Validate DOS header ("MZ").
    if (data[0] != 'M' || data[1] != 'Z') return false;

    // Read e_lfanew at offset 0x3C.
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[0x3C]);
    if (peOffset + 24 > data.size()) return false;

    // Validate PE signature ("PE\0\0").
    if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' ||
        data[peOffset + 2] != 0 || data[peOffset + 3] != 0) return false;

    // TimeDateStamp offset: PE signature (4) + Machine (2) + NumberOfSections (2).
    outOffset = peOffset + 8;
    return outOffset + 4 <= data.size();
}


// Converts year/month/day/hour/minute/second (UTC) to a Unix timestamp.
// Based on Howard Hinnant's days_from_civil (public domain).
static int64_t DaysFromCivil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// Builds a Unix timestamp from a UTC date and time.
static uint32_t MakeTimestamp(int year, int month, int day,
    int hour, int minute, int second) {
    int64_t days = DaysFromCivil(year, static_cast<unsigned>(month),
        static_cast<unsigned>(day));
    int64_t secs = days * 86400 + hour * 3600 + minute * 60 + second;
    return static_cast<uint32_t>(secs);
}

// Formats a Unix timestamp as a readable UTC string.
static std::string TimestampToString(uint32_t ts) {
    time_t t = static_cast<time_t>(ts);
    struct tm tmUtc {};
    gmtime_s(&tmUtc, &t);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
        tmUtc.tm_year + 1900, tmUtc.tm_mon + 1, tmUtc.tm_mday,
        tmUtc.tm_hour, tmUtc.tm_min, tmUtc.tm_sec);
    return std::string(buf);
}

static void PrintUsage() {
    std::cout <<
        "PEStomp - modifies the TimeDateStamp of a PE file\n"
        "\n"
        "Usage:\n"
        "  PEStomp.exe <file.exe> --year <start> <end>   random year in range\n"
        "  PEStomp.exe <file.exe> --random               random 1990-2030\n"
        "  PEStomp.exe <file.exe> --zero                 set to zero\n"
        "  PEStomp.exe <file.exe> --now                  current timestamp\n"
        "  PEStomp.exe <file.exe> --set <hex>            custom value (e.g. 0x5A1B2C3D)\n"
        "\n"
        "Examples:\n"
        "  PEStomp.exe ExternalV7.exe --year 2022 2024\n"
        "  PEStomp.exe ExternalV7.exe --year 2020 2020   (only 2020)\n"
        "  PEStomp.exe ExternalV7.exe --set 0x63000000\n";
}

int main(int argc, char** argv) {
    if (argc < 3) { PrintUsage(); return 1; }

    std::string path = argv[1];
    std::string mode = argv[2];

    // Load the target file into memory.
    std::vector<uint8_t> data;
    if (!ReadFileBytes(path, data)) {
        std::cerr << "[!] Failed to read file: " << path << "\n";
        return 1;
    }

    // Locate the TimeDateStamp field.
    size_t offset = 0;
    if (!FindTimeDateStampOffset(data, offset)) {
        std::cerr << "[!] Not a valid PE file (MZ/PE signature missing)\n";
        return 1;
    }

    uint32_t oldValue = *reinterpret_cast<const uint32_t*>(&data[offset]);
    uint32_t newValue = 0;

    if (mode == "--year" && argc >= 5) {
        // Random year within the given range.
        int startYear = std::atoi(argv[3]);
        int endYear = std::atoi(argv[4]);
        if (startYear > endYear) std::swap(startYear, endYear);
        if (startYear < 1970 || endYear > 2100) {
            std::cerr << "[!] Years must be between 1970 and 2100\n";
            return 1;
        }

        std::random_device rd;
        std::mt19937 gen(rd());

        uint32_t startTs = MakeTimestamp(startYear, 1, 1, 0, 0, 0);
        uint32_t endTs = MakeTimestamp(endYear, 12, 31, 23, 59, 59);

        std::uniform_int_distribution<uint32_t> dist(startTs, endTs);
        newValue = dist(gen);
    }
    else if (mode == "--random") {
        // Random timestamp between 1990 and 2030.
        std::random_device rd;
        std::mt19937 gen(rd());
        uint32_t startTs = MakeTimestamp(1990, 1, 1, 0, 0, 0);
        uint32_t endTs = MakeTimestamp(2030, 12, 31, 23, 59, 59);
        std::uniform_int_distribution<uint32_t> dist(startTs, endTs);
        newValue = dist(gen);
    }
    else if (mode == "--zero") {
        newValue = 0;
    }
    else if (mode == "--now") {
        auto now = std::chrono::system_clock::now();
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        newValue = static_cast<uint32_t>(secs);
    }
    else if (mode == "--set" && argc >= 4) {
        std::string hexStr = argv[3];
        if (hexStr.rfind("0x", 0) == 0 || hexStr.rfind("0X", 0) == 0)
            hexStr = hexStr.substr(2);
        newValue = static_cast<uint32_t>(std::stoul(hexStr, nullptr, 16));
    }
    else {
        PrintUsage();
        return 1;
    }

    // Write the new value into the buffer.
    *reinterpret_cast<uint32_t*>(&data[offset]) = newValue;

    if (!WriteFileBytes(path, data)) {
        std::cerr << "[!] Failed to write file: " << path << "\n";
        return 1;
    }

    std::cout << "[+] TimeDateStamp updated\n"
        << "    File: " << path << "\n"
        << "    Old:  0x" << std::hex << oldValue << std::dec
        << "  (" << TimestampToString(oldValue) << ")\n"
        << "    New:  0x" << std::hex << newValue << std::dec
        << "  (" << TimestampToString(newValue) << ")\n";

    return 0;
}