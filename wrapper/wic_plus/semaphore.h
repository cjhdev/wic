/* Copyright (c) 2023 Cameron Harper
 *
 * */

#ifndef SEMAPHORE_H
#define SEMAPHORE_H

#include <mutex>
#include <condition_variable>

#include <cstdint>
#include <cstdbool>

namespace WIC {

    class Semaphore {

    private:

        std::condition_variable cv;
        std::mutex mutex;

        uint32_t count;
        uint32_t max;

    public:

        Semaphore(uint32_t count = 0, uint32_t max = UINT32_MAX);
        void acquire();
        void release();

        bool try_acquire();
    };
};

#endif
