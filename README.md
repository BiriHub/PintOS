# Project 2 : Timer Sleep

### Overview
In this project, you will re-implement the `timer_sleep()` function in PintOS to avoid busy waiting and to make it efficient.

### Current implementation
The current `timer_sleep()` function in `devices/timer.c` uses a busy wait approach, which is suboptimal:

```c
void timer_sleep (int64_t ticks)
{
  int64_t start = timer_ticks();
  while (timer_elapsed(start) < ticks)
    thread_yield();
}
```
<!-- ## My solution

### thread.h 
struct thread has been  -->