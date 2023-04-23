// Axel '0vercl0k' Souchet - July 10 2021
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <array>
#include <cstdio>

void FuzzMe(const char *buffer, uint32_t size) {
  if (size < 10) {
    return;
  }

  if (buffer[0] == 'F') {
    if (buffer[1] == 'U') {
      if (buffer[2] == 'Z') {
        if (buffer[3] == 'Z') {
          if (buffer[4] == 'I') {
            if (buffer[5] == 'N') {
              if (buffer[6] == 'G') {
                if (buffer[7] == '!') {
                  uint32_t data = *(uint32_t *)nullptr;
                  printf("%d", data);
                }
              }
            }
          }
        }
      }
    }
  }
}

int main() {
  std::array<uint8_t, 1024> Buffer;
  if (getenv("BREAK") != nullptr) {
    __debugbreak();
  }

  FuzzMe((const char *)Buffer.data(), Buffer.size());

  return EXIT_SUCCESS;
}