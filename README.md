# Project 3 : Schedulers

## Overview

This project aims to enhance the PintOS operating system by implementing two types of schedulers: a simple ___priority scheduler___ and an ___advanced scheduler___ that dynamically adjusts thread priorities based on their CPU usage, thread's _niceness_ and on the actual average system load to prevent starvation.

### Priority Scheduler

The priority scheduler selects the next thread to run based on the highest priority. If multiple threads have the same highest priority, they are alternated using a round-robin method.

#### Requirements

- **Priority Range:** Integer values from 0 to 63 (inclusive).
- **Pre-defined Priorities:** 
  - `PRI_MIN = 0`
  - `PRI_DEFAULT = 31`
  - `PRI_MAX = 63`
- **Function Modifications:**
  - `next_thread_to_run()`: Return the thread with the highest priority.
  - `thread_set_priority()`: Make the current thread yield if its new priority is no longer the highest.
  - `thread_create()`: Make the current thread yield if a higher priority thread is created.

### Advanced Scheduler

The advanced scheduler adjusts thread priorities based on a "nice" value and recent CPU usage to ensure CPU-hungry threads lose priority over time.

#### Requirements

- **Nice Value:** Integer ranging from -20 to 20, default is 0.
- **Recent CPU:** Indicates the CPU usage of a thread recently.
- **Load Average:** A global variable representing the system load (number of ready and running threads per second over the last minute).
  
#### Functions to Implement

- `thread_set_nice(int)`: Update the thread’s nice value, recalculate its priority, and yield if necessary.
- `thread_get_nice()`: Return the thread’s nice value.
- `thread_get_load_avg()`: Return `load_avg * 100`.
- `thread_get_recent_cpu()`: Return the current thread’s recent CPU usage multiplied by 100.

#### Required Variables

- **Nice (per thread):** Initial value set by the user and modifiable via `thread_set_nice()`.
- **Load Average (global):** Updated as `(59/60) * load_avg + (1/60) * ready or running threads`.
- **Recent CPU (per thread):** Initially 0. Updated every second and on each tick for the current thread.
- **Priority (per thread):** Calculated as `PRI_MAX - (recent_cpu / 4) - (nice * 2)`, updated every 4 ticks.

## Files changed
* pintos/threads/**thread.h**
* pintos/threads/**thread.c**

## TESTS (_10/27 tests FAIL_)
The implementation makes **pass** the following tests :

* tests/threads/alarm-single

* tests/threads/alarm-multiple
* tests/threads/alarm-simultaneous 
* tests/threads/alarm-priority 
* tests/threads/alarm-zero
* tests/threads/alarm-negative 
* tests/threads/priority-change
* tests/threads/priority-fifo
* tests/threads/priority-preempt
* tests/threads/mlfqs-load-I 
* tests/threads/mlfqs-load-60 
* tests/threads/mlfqs-load-avg 
* tests/threads/mlfqs-recent-I 
* tests/threads/mlfqs-fair-2 
* tests/threads/mlfqs-fair-20 
* tests/threads/mlfqs-nice-2 
* tests/threads/mlfqs-nice-10