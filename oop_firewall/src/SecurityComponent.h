#pragma once
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
//  Abstract base – all major subsystems inherit from this
// ─────────────────────────────────────────────────────────────────────────────
class SecurityComponent {
public:
    virtual ~SecurityComponent() = default;

    virtual bool initialize() = 0;
    virtual void shutdown()   = 0;
};
