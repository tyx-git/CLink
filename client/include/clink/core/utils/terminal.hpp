#pragma once

#include <string>
#include <iostream>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace clink::core::utils {

enum class Color {
    Default,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite
};

class Terminal {
public:
    static void initialize() {
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return;
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
#endif
    }

    static std::string color_code(Color color) {
        switch (color) {
            case Color::Red: return "\033[31m";
            case Color::Green: return "\033[32m";
            case Color::Yellow: return "\033[33m";
            case Color::Blue: return "\033[34m";
            case Color::Magenta: return "\033[35m";
            case Color::Cyan: return "\033[36m";
            case Color::White: return "\033[37m";
            case Color::BrightRed: return "\033[91m";
            case Color::BrightGreen: return "\033[92m";
            case Color::BrightYellow: return "\033[93m";
            case Color::BrightBlue: return "\033[94m";
            case Color::BrightMagenta: return "\033[95m";
            case Color::BrightCyan: return "\033[96m";
            case Color::BrightWhite: return "\033[97m";
            default: return "\033[0m";
        }
    }

    static std::string reset_code() {
        return "\033[0m";
    }

    static void print(std::string_view text, Color color = Color::Default) {
        if (color != Color::Default) {
            std::cout << color_code(color) << text << reset_code();
        } else {
            std::cout << text;
        }
    }

    static void println(std::string_view text, Color color = Color::Default) {
        print(text, color);
        std::cout << std::endl;
    }

    static void clear_screen() {
        std::cout << "\033[2J\033[H" << std::flush;
    }

    static void move_cursor(int row, int col) {
        std::cout << "\033[" << row << ";" << col << "H" << std::flush;
    }

    static void hide_cursor() {
        std::cout << "\033[?25l" << std::flush;
    }

    static void show_cursor() {
        std::cout << "\033[?25h" << std::flush;
    }
};

} // namespace clink::core::utils
