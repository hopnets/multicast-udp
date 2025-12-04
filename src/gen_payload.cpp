#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <ctime>


#define CHUNK_SIZE (1024 * 1024) // 1 MB

const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// Converts a size string like "10MB", "1.5GiB", "300K", or "500" (default MB) into bytes.
std::size_t parse_size(const std::string &str) {
    double value;
    std::string unit = "MB";  // Default unit is MB
    std::size_t i = 0;

    // Extract numeric part
    while (i < str.size() && (std::isdigit(static_cast<unsigned char>(str[i])) ||
                              str[i] == '.' || str[i] == '-')) {
        ++i;
    }

    if (i == 0) {
        return 0; // no valid number
    }

    try {
        value = std::stod(str);
    } catch (...) {
        return 0;
    }

    if (i < str.size()) {
        unit = str.substr(i);
    }

    // Convert unit to uppercase to allow lowercase input like "kb", "mib", etc.
    std::transform(unit.begin(), unit.end(), unit.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (unit == "B")
        return static_cast<std::size_t>(value);
    else if (unit == "KB" || unit == "K")
        return static_cast<std::size_t>(value * 1024ULL);
    else if (unit == "MB" || unit == "M")
        return static_cast<std::size_t>(value * 1024ULL * 1024ULL);
    else if (unit == "GB" || unit == "G")
        return static_cast<std::size_t>(value * 1024ULL * 1024ULL * 1024ULL);
    else if (unit == "TB" || unit == "T")
        return static_cast<std::size_t>(value * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
    else if (unit == "KIB")
        return static_cast<std::size_t>(value * 1024ULL);
    else if (unit == "MIB")
        return static_cast<std::size_t>(value * 1024ULL * 1024ULL);
    else if (unit == "GIB")
        return static_cast<std::size_t>(value * 1024ULL * 1024ULL * 1024ULL);
    else if (unit == "TIB")
        return static_cast<std::size_t>(value * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
    else {
        std::cerr << "Unknown unit: " << unit
                  << ". Use B, KB, MB, GB, TB, KiB, MiB, etc.\n";
        return 0;
    }
}

void fill_random(char *buffer, std::size_t size) {
    static const std::size_t charset_len = sizeof(charset) - 1;
    for (std::size_t i = 0; i < size; ++i) {
        buffer[i] = charset[std::rand() % charset_len];
    }
}

void print_help(const char *prog) {
    std::cout << "Usage: " << prog << " <size> <output_filename>\n";
    std::cout << "  size formats accepted:\n";
    std::cout << "    - B, KB, MB, GB, TB (e.g., 100B, 200KB, 10MB, 1GB, 2TB)\n";
    std::cout << "    - K, M, G, T (e.g., 10M, 5G)\n";
    std::cout << "    - Binary units: KiB, MiB, GiB, TiB (e.g., 20MiB)\n";
    std::cout << "    - Default unit: MB if unspecified (e.g., 100 == 100MB)\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << prog << " 10MB payload.bin\n";
}

int main(int argc, char *argv[]) {
    if (argc != 3 || std::string(argv[1]) == "-h") {
        print_help(argv[0]);
        return 1;
    }

    std::string size_str = argv[1];
    std::size_t total_bytes = parse_size(size_str);
    if (total_bytes == 0) {
        std::cerr << "Invalid size: " << size_str << "\n";
        return 1;
    }

    const char *filename = argv[2];

    std::cout << "Generating " << filename
              << " with size: " << total_bytes << " bytes\n";

    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs) {
        std::perror("ofstream");
        return 1;
    }

    std::vector<char> buffer(CHUNK_SIZE);

    std::srand(static_cast<unsigned>(std::time(nullptr)));

    for (std::size_t written = 0; written < total_bytes; written += CHUNK_SIZE) {
        std::size_t chunk = (total_bytes - written < CHUNK_SIZE)
                                ? (total_bytes - written)
                                : CHUNK_SIZE;
        fill_random(buffer.data(), chunk);
        ofs.write(buffer.data(), static_cast<std::streamsize>(chunk));
        if (!ofs) {
            std::cerr << "Error writing to file.\n";
            return 1;
        }
    }

    return 0;
}
