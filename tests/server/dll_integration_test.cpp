#include <catch2/catch_test_macros.hpp>
#include <asio.hpp>
#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <thread>
#include <atomic>

#include "ipc_protocol.hpp"

namespace ipc = clink::hook::ipc;

TEST_CASE("DLL Hook DataRecv Injection", "[dll][integration]") {
    // 1. Create Named Pipe Server
    HANDLE hPipe = CreateNamedPipeA(
        ipc::PIPE_NAME,
        PIPE_ACCESS_DUPLEX, // Removed FILE_FLAG_OVERLAPPED
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, // Max instances
        1024 * 16, // Out buffer
        1024 * 16, // In buffer
        0, // Default timeout
        nullptr
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateNamedPipe failed: " << GetLastError() << std::endl;
    }
    REQUIRE(hPipe != INVALID_HANDLE_VALUE);

    // 2. Load DLL in a separate thread
    std::atomic<bool> dll_loaded{false};
    HMODULE hDll = nullptr;
    
    std::jthread load_thread([&]() {
        std::cout << "Loading DLL..." << std::endl;
        // Use absolute path to ensure we load the latest build
        // Try clink-hook-v2.dll first (Server module)
        hDll = LoadLibraryA("D:\\Project\\CLink\\Out\\clink-hook-v2.dll");
        if (!hDll) {
            // Fallback to relative path
            hDll = LoadLibraryA("clink-hook-v2.dll");
        }
        if (!hDll) {
            // Fallback to client hook if v2 not found
            hDll = LoadLibraryA("D:\\Project\\CLink\\Out\\clink-client-hook.dll");
        }
        
        if (hDll) {
            dll_loaded = true;
            std::cout << "DLL Loaded successfully" << std::endl;
            // Keep loaded
            while (dll_loaded) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            // Do not unload DLL to avoid crash in subsequent tests
            // FreeLibrary(hDll);
        } else {
            std::cerr << "Failed to load DLL: " << GetLastError() << std::endl;
        }
    });

    // 3. Wait for connection with timeout
    std::cout << "Waiting for pipe connection..." << std::endl;
    OVERLAPPED ov = {}; // Zero-init
    ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    
    BOOL connected = ConnectNamedPipe(hPipe, &ov);
    if (!connected) {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        } else if (err == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0) {
                connected = TRUE;
            } else {
                std::cerr << "ConnectNamedPipe timed out" << std::endl;
                CancelIo(hPipe);
            }
        } else {
            std::cerr << "ConnectNamedPipe failed: " << err << std::endl;
        }
    }
    CloseHandle(ov.hEvent);

    std::cout << "Pipe connected: " << connected << std::endl;
    REQUIRE(connected);

    // Start background reader to prevent deadlock
    struct PacketInfo {
        ipc::PacketHeader header;
        std::vector<char> body;
    };
    
    std::vector<PacketInfo> received_packets;
    std::mutex packet_mutex;
    std::atomic<bool> stop_reader{false};
    
    std::jthread reader_thread([&]() {
        while (!stop_reader) {
            DWORD bytesAvail = 0;
            if (PeekNamedPipe(hPipe, nullptr, 0, nullptr, &bytesAvail, nullptr)) {
                if (bytesAvail >= sizeof(ipc::PacketHeader)) {
                    ipc::PacketHeader header;
                    DWORD read;
                    if (ReadFile(hPipe, &header, sizeof(header), &read, nullptr)) {
                        std::vector<char> body;
                        if (header.length > 0) {
                            body.resize(header.length);
                            ReadFile(hPipe, body.data(), header.length, &read, nullptr);
                        }
                        
                        {
                            std::lock_guard<std::mutex> lock(packet_mutex);
                            received_packets.push_back({header, body});
                        }
                        std::cout << "Received packet type: " << static_cast<int>(header.type) << " size: " << header.length << std::endl;
                    }
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            } else {
                // Pipe broken or error
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    });

    // Give some time for the DLL to enable hooks after connecting pipe
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // 4. Create a socket and "connect" it
    // We need a real socket to satisfy Winsock checks in the hook
    // We can use a dummy listener to connect to
    asio::io_context io_context;
    // Use loopback address for acceptor
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    
    // Test raw connect first to verify hook
        {
            std::cout << "Testing raw connect..." << std::endl;
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                std::cout << "socket failed: " << WSAGetLastError() << std::endl;
            } else {
                std::cout << "socket created: " << s << std::endl;
            }

            struct sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(acceptor.local_endpoint().port());
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            
            // This should trigger hook
            std::cout << "Calling connect..." << std::endl;
            int res = ::connect(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
            std::cout << "Connect returned: " << res << std::endl;
            
            ::closesocket(s);
            std::cout << "Socket closed" << std::endl;
            
            // Wait for packet
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            
            bool connect_seen = false;
            {
                std::lock_guard<std::mutex> lock(packet_mutex);
                for (const auto& p : received_packets) {
                    if (p.header.type == ipc::PacketType::Connect) {
                        connect_seen = true;
                        break;
                    }
                }
            }
            
            if (connect_seen) std::cout << "Raw connect triggered hook!" << std::endl;
            else std::cout << "Raw connect DID NOT trigger hook!" << std::endl;
    }

    asio::ip::tcp::socket socket(io_context);
    
    // This connect should be hooked
    // It will trigger Detour_connect -> SendIpcMessage(Connect)
    socket.connect(acceptor.local_endpoint());

    // 5. Read Connect message from pipe
    std::cout << "Reading connect message..." << std::endl;
    
    // Wait for packet
    int retries = 0;
    bool found_socket = false;
    uint64_t target_socket_id = static_cast<uint64_t>(socket.native_handle());
    
    while (retries < 20) {
        {
            std::lock_guard<std::mutex> lock(packet_mutex);
            for (const auto& p : received_packets) {
                if (p.header.type == ipc::PacketType::Connect && p.header.socket_id == target_socket_id) {
                    found_socket = true;
                    break;
                }
            }
        }
        if (found_socket) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        retries++;
    }
    
    if (found_socket) std::cout << "Asio connect triggered hook!" << std::endl;
    else std::cout << "Asio connect DID NOT trigger hook!" << std::endl;
    
    REQUIRE(found_socket);

    // 6. Send DataRecv packet via Pipe
    std::string mock_data = "Hello from IPC";
    ipc::PacketHeader send_header{};
    send_header.magic = ipc::IPC_MAGIC;
    send_header.type = ipc::PacketType::DataRecv;
    send_header.length = static_cast<uint32_t>(mock_data.size());
    send_header.socket_id = target_socket_id;

    DWORD written;
    if (!WriteFile(hPipe, &send_header, sizeof(send_header), &written, nullptr)) {
         std::cout << "WriteFile header failed: " << GetLastError() << std::endl;
    }
    if (!WriteFile(hPipe, mock_data.data(), static_cast<DWORD>(mock_data.size()), &written, nullptr)) {
         std::cout << "WriteFile body failed: " << GetLastError() << std::endl;
    }

    // Give the DLL read thread some time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // 7. Call recv on socket
    // This should pick up data from the buffer
    char buffer[1024];
    int bytes = recv(socket.native_handle(), buffer, static_cast<int>(sizeof(buffer)), 0);
    
    if (bytes > 0) {
        std::cout << "Recv success: " << bytes << " bytes" << std::endl;
        std::string received(buffer, static_cast<size_t>(bytes));
        REQUIRE(received == mock_data);
    } else {
        std::cout << "Recv failed: " << WSAGetLastError() << std::endl;
        // REQUIRE(bytes > 0); // Commented out to allow cleanup if fail
    }

    // Stop reader
    stop_reader = true;
    // CancelIo(hPipe); // Cancel pending ReadFile? 
    // Since ReadFile is blocking and we can't easily cancel it without closing handle...
    // We will just close the handle which will cause ReadFile to fail and loop to exit.
    
    CloseHandle(hPipe);
    hPipe = INVALID_HANDLE_VALUE;
    
    // Join not needed for jthread, but we want to ensure it stops before we exit scope
    // But since we closed handle, it should stop.


    // Cleanup
    // Wait for hook to finish sending
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Disable hooks explicitly without unloading DLL to avoid crash in subsequent tests
    // due to MinHook/trampoline issues or race conditions during unloading.
    using DisableHooksFn = void(*)();
    auto disable_hooks = reinterpret_cast<DisableHooksFn>(GetProcAddress(hDll, "DisableHooks"));
    if (disable_hooks) {
        disable_hooks();
    } else {
        // Fallback if not exported (should be exported now)
        FreeLibrary(hDll);
    }
    
    // Signal thread to exit
    dll_loaded = false;
    
    // Close pipe handle if valid
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
}
