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
### TESTS (20/27 tests FAIL)
The implementation makes **pass** the next tests:

* tests/threads/alarm-single 

* tests/threads/alarm-multiple
* tests/threads/alarm-simultaneous
* tests/threads/alarm-zero
* tests/threads/alarm-negative
* tests/threads/mlfqs-fair-2 
* tests/threads/ml fqs-fair-20