#include <iostream>
#include <algorithm>
#include <exception>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <unordered_map>
#include <dirent.h>      // For directory reading (listing PIDs from /proc)
#include <sys/types.h>   // For pid_t
#include <cctype>        // For std::isdigit
#include <fstream> // 用于文件流操作 std::ofstream
#include <iomanip>
#include <limits>    // 用于 std::numeric_limits (如果清理输入缓冲区时用到)
#include "system_public.h"
#include "scanner.h"
#include "stopwatch.h"

// Forward declaration from the original file if you keep it separate
void print_results(Scanner& scanner, int count);
std::string GetInput(); // Keep if you want to get scan parameters once 
std::string GetInputLower(); // Keep if you want to get scan parameters once
int GetInputInt(); // Keep if you want to get scan parameters once
void set_alignment(Scanner& scanner); // Keep for setting global scan params
void set_value_type(Scanner& scanner); // Keep for setting global scan params
void set_compare_type(Scanner& scanner); // Keep for setting global scan params


// Function to get all numeric PIDs from /proc (Linux specific)
std::vector<pid_t> getAllPids() {
    std::vector<pid_t> pids;
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return pids;
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type == DT_DIR) { // Check if it's a directory
            std::string name = entry->d_name;
            // Check if the directory name consists only of digits
            bool is_pid_dir = !name.empty() && std::all_of(name.begin(), name.end(), ::isdigit);
            if (is_pid_dir) {
                try {
                    pids.push_back(std::stoi(name));
                }
                catch (const std::out_of_range& oor) {
                    std::cerr << "PID out of range: " << name << std::endl;
                }
                catch (const std::invalid_argument& ia) {
                    std::cerr << "Invalid PID string (should not happen after isdigit check): " << name << std::endl;
                }
            }
        }
    }
    closedir(proc_dir);
    std::sort(pids.begin(), pids.end()); // Optional: sort PIDs
    return pids;
}

std::string getProcessNameByPid(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream comm_file(path);
    std::string name;
    if (comm_file.is_open()) {
        std::getline(comm_file, name); // 读取整行，进程名通常不含空格，且getline不包含末尾换行符
        comm_file.close();
        // /comm 文件中的名称可能包含一个末尾的换行符，getline通常会处理掉
        // 但为保险起见，可以再检查一下（尽管对于getline默认行为通常不需要）
        if (!name.empty() && name.back() == '\n') {
            name.pop_back();
        }
    }
    return name; // 如果文件无法打开或为空，返回空字符串
}
// --- Definitions for functions from the original main.cpp if you keep them ---
// (GetInput, GetInputLower, GetInputInt, print_results, set_alignment, set_value_type, set_compare_type)
// You can copy them from the original memoryscanner/main.cpp file

bool print_results(Scanner& scanner, int count_limit, std::ostream& out_stream, pid_t current_pid, const std::string& process_name) {
    auto& results = scanner.get_results();
    bool wrote_pid_header = false;
    int results_written_count = 0;

    for (const auto& adr : results) {
        char mem_buffer[65];
        size_t bytes_read = 0;
        const size_t bytes_to_read = 64;
        bool content_successfully_read = false;

        if (sys_seek_memory(adr.address)) {
            if (sys_read_memory(adr.address, mem_buffer, bytes_to_read, &bytes_read)) {
                if (bytes_read > 0) {
                    mem_buffer[bytes_read] = '\0';
                    content_successfully_read = true;
                }
            }
        }

        if (content_successfully_read) {
            if (!wrote_pid_header) {
                // 输出PID和进程名
                out_stream << "PID: " << current_pid
                           << " (Name: " << (process_name.empty() ? "[unknown]" : process_name) << ")\n";
                wrote_pid_header = true;
            }

            out_stream << static_cast<void*>(adr.address) << " : ";

            switch (scanner.settings.value_type) {
                case ValueType::Int8:   out_stream << static_cast<int>(adr.value.int8); break;
                // ... (其他 case 不变)
                case ValueType::Int16:  out_stream << adr.value.int16; break;
                case ValueType::Int32:  out_stream << adr.value.int32; break;
                case ValueType::Int64:  out_stream << adr.value.int64; break;
                case ValueType::Float:  out_stream << adr.value.float_value; break;
                case ValueType::Double: out_stream << adr.value.double_value; break;
                case ValueType::String: out_stream << "[String Search Result]"; break;
                default:                out_stream << "[Unknown Value Type]"; break;
            }

            out_stream << " | Content: \"";
            for (size_t j = 0; j < bytes_read; ++j) {
                if (isprint(static_cast<unsigned char>(mem_buffer[j]))) {
                    out_stream << mem_buffer[j];
                } else {
                    out_stream << ".";
                }
            }
            out_stream << "\"\n";

            results_written_count++;
            if (count_limit != 0 && results_written_count >= count_limit) {
                out_stream << "(Showing first " << count_limit << " successfully read results for this PID)\n";
                break;
            }
        }
    }

    if (wrote_pid_header) {
        out_stream << "-------------------------------------------\n";
    }
    out_stream << std::flush;

    std::cout << "PID " << current_pid << (process_name.empty() ? "" : " (Name: " + process_name + ")")
              << " - Potential matches: " << results.size()
              << ". Successfully read and wrote " << results_written_count << " to res.txt." << std::endl;

    return wrote_pid_header;
}

// Add other helper functions like GetInput, set_value_type etc. if you want to prompt for scan parameters once.
// For brevity, these are omitted but you would copy them from the original main.cpp.

// Dummy implementations for GetInput and other interactive setup functions if you want to quickly compile.
// Replace these with actual implementations from the original file if you want interactive setup.
std::string GetInput() { std::string s; std::cin >> s; return s; }
std::string GetInputLower() { std::string s = GetInput(); std::transform(s.begin(), s.end(), s.begin(), ::tolower); return s; }
int GetInputInt() { try { return std::stoi(GetInput()); } catch (...) { return 0; } }

void set_alignment(Scanner::Settings& settings) { // Modified to take settings directly
    std::cout << "Enter alignment (e.g., 1, 2, 4, 8):\n";
    settings.alignment = GetInputInt();
}

void set_value_type(Scanner::Settings& settings) { // Modified to take settings directly
    const std::unordered_map<std::string, ValueType> value_types{
        {"int8", ValueType::Int8}, {"int16", ValueType::Int16}, {"int32", ValueType::Int32},
        {"int64", ValueType::Int64}, {"float", ValueType::Float}, {"double", ValueType::Double},
        {"string", ValueType::String}
    };
    for (;;) {
        std::cout << "ValueType: int8, int16, int32, int64, float, double, string\n>> ";
        std::string input = GetInputLower();
        if (input == "!q") break;
        auto it = value_types.find(input);
        if (it != value_types.end()) {
            settings.value_type = it->second;
            break;
        }
        std::cout << "Invalid ValueType selection\n";
    }
}

void set_compare_type(Scanner::Settings& settings) { // Modified to take settings directly
    const std::unordered_map<std::string, CompareType> compare_types{
        {"equal", CompareType::Equal}, {"less", CompareType::Less}, {"greater", CompareType::Greater},
        {"unknown", CompareType::Unknown}, {"increased", CompareType::Increased}, {"decreased", CompareType::Decreased},
        {"unchanged", CompareType::Unchanged}, {"changed", CompareType::Changed}
    };
    for (;;) {
        std::cout << "CompareType: equal, less, greater, unknown, increased, decreased, unchanged, changed\n>> ";
        std::string input = GetInputLower();
        if (input == "!q") break;
        auto it = compare_types.find(input);
        if (it != compare_types.end()) {
            settings.compare_type = it->second;
            break;
        }
        std::cout << "Invalid CompareType selection\n";
    }
}

int main() {
    std::ofstream outfile("res.txt");
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not open res.txt for writing." << std::endl;
        return 1;
    }

    time_t now = time(0);
    outfile << "Memory Scan Results - " << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << "\n";
    outfile << "===========================================\n\n";

    bool any_match_found_in_run = false;

    std::vector<pid_t> all_pids = getAllPids();

    if (all_pids.empty()) {
        std::cout << "No processes found or failed to list processes from /proc." << std::endl;
    } else {
        std::cout << "Found " << all_pids.size() << " processes. Scanning..." << std::endl;
    }

    Scanner::Settings common_scan_settings;
    // ... (设置 common_scan_settings 和 scan_value_str 的代码不变)
    std::cout << "Setup global scan parameters:\n";
    set_alignment(common_scan_settings);
    set_value_type(common_scan_settings);
    set_compare_type(common_scan_settings);

    std::string scan_value_str;
     if (common_scan_settings.compare_type != CompareType::Unknown &&
        common_scan_settings.compare_type != CompareType::Increased &&
        common_scan_settings.compare_type != CompareType::Decreased &&
        common_scan_settings.compare_type != CompareType::Unchanged &&
        common_scan_settings.compare_type != CompareType::Changed) {
        std::cout << "Enter value to scan for:\n>> ";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::getline(std::cin, scan_value_str);
    }


    for (pid_t pid : all_pids) {
        std::string proc_name = getProcessNameByPid(pid); // 获取进程名

        // 更新控制台输出以包含进程名
        std::cout << "\nScanning PID: " << pid
                  << (proc_name.empty() ? "" : " (Name: " + proc_name + ")")
                  << std::endl;

        try {
            Scanner scanner{static_cast<size_t>(pid)};
            scanner.settings = common_scan_settings;

            StopWatch sw{"Scan time for PID " + std::to_string(pid) + (proc_name.empty() ? "" : " (" + proc_name + ")")};

            if (common_scan_settings.compare_type == CompareType::Unknown) {
                 scanner.find("");
            } else {
                 scanner.find(scan_value_str);
            }
            
            // 调用 print_results 时传入进程名
            if (print_results(scanner, 0, outfile, pid, proc_name)) {
                any_match_found_in_run = true;
            }

        } catch (const std::runtime_error& ex) {
            std::cerr << "Error scanning PID " << pid << (proc_name.empty() ? "" : " (" + proc_name + ")")
                      << ": " << ex.what()
                      << " (Perhaps permission denied or process terminated?)" << std::endl;
        } catch (const std::exception& ex_gen) {
            std::cerr << "An unexpected error occurred for PID " << pid << (proc_name.empty() ? "" : " (" + proc_name + ")")
                      << ": " << ex_gen.what() << std::endl;
        }
    }

    if (!any_match_found_in_run) {
        outfile << "No matching content found in this scan run.\n";
    }
    outfile << "\n===========================================\n";
    outfile << "Scan finished.\n";
    outfile.close();

    std::cout << "\nFinished scanning all processes. Results selectively saved to res.txt" << std::endl;
    return 0;
}
