#include "semaphore.h"

using namespace WIC;

Semaphore::Semaphore(uint32_t count, uint32_t max)
    :
    count(count),
    max(max)
{
    if(count > max){

        count = max;
    }
}

void
Semaphore::acquire()
{
    std::unique_lock<std::mutex> lock(mutex);

    for(;;){

        if(count > 0U){

            count--;
            break;
        }
        else{

            cv.wait(lock);
        }
    }
}

bool
Semaphore::try_acquire()
{
    std::unique_lock<std::mutex> lock(mutex);
    bool retval;

    if(count > 0U){

        count--;
        retval = true;
    }
    else{

        retval = false;
    }

    return retval;
}

void
Semaphore::release()
{
    std::unique_lock<std::mutex> lock(mutex);

    if(count < max){

        count++;

        cv.notify_one();
    }
}


