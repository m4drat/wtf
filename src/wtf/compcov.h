// Theodor Arsenij 'm4drat' - May 26 2023

#pragma once

//
// Compcov maximum comparison length. Everything above this length will be
// ignored.
//

constexpr uint64_t COMPCOV_MAX_CMP_LENGTH = 34;

//
// Setup compcov hooks on different implementations of comparison functions:
// ntdll!strcmp, ucrtbase!strcmp, etc.
//

bool SetupCompcovHooks();