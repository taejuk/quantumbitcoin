// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/stdin.h>

#include <cstdio>

#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#include <poll.h>
#endif

// https://stackoverflow.com/questions/1413445/reading-a-password-from-stdcin
// enable이 false이면 입력할 때, 보이지 않는다 -> 비밀번호입력할 때 사용한다.
void SetStdinEcho(bool enable)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if (!enable) {
        mode &= ~ENABLE_ECHO_INPUT;
    } else {
        mode |= ENABLE_ECHO_INPUT;
    }
    SetConsoleMode(hStdin, mode);
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}
// 표준 입력이 터미널인지 확인하는 함수
bool StdinTerminal()
{
#ifdef WIN32
    return _isatty(_fileno(stdin));
#else
    return isatty(fileno(stdin));
#endif
}

bool StdinReady()
{
    if (!StdinTerminal()) {
        return true;
    }
#ifdef WIN32
    return false;
#else
    struct pollfd fds;
    fds.fd = STDIN_FILENO;
    fds.events = POLLIN;
    return poll(&fds, 1, 0) == 1;
#endif
}

NoechoInst::NoechoInst() { SetStdinEcho(false); }
NoechoInst::~NoechoInst() { SetStdinEcho(true); }
