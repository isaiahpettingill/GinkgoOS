//! Fixed-capacity stackless cooperative task scheduling.
//!
//! A task runs one bounded step and returns `TaskPoll::Pending` to yield or
//! `TaskPoll::Complete` to release its slot. Continuations must be represented
//! explicitly in `TaskState`; tasks do not receive independent stacks.

pub const TASK_STATE_WORDS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskPoll {
    Pending,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskState {
    words: [usize; TASK_STATE_WORDS],
}

impl TaskState {
    pub const fn new() -> Self {
        Self {
            words: [0; TASK_STATE_WORDS],
        }
    }

    pub const fn from_words(words: [usize; TASK_STATE_WORDS]) -> Self {
        Self { words }
    }

    pub fn get(&self, index: usize) -> Option<usize> {
        self.words.get(index).copied()
    }

    pub fn set(&mut self, index: usize, value: usize) -> bool {
        if let Some(word) = self.words.get_mut(index) {
            *word = value;
            true
        } else {
            false
        }
    }

    pub fn words(&self) -> &[usize; TASK_STATE_WORDS] {
        &self.words
    }

    pub fn words_mut(&mut self) -> &mut [usize; TASK_STATE_WORDS] {
        &mut self.words
    }
}

impl Default for TaskState {
    fn default() -> Self {
        Self::new()
    }
}

pub type TaskFn<C> = fn(&mut C, &mut TaskState) -> TaskPoll;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnError {
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Idle,
    Pending,
    Completed,
}

pub struct Scheduler<C, const TASKS: usize> {
    slots: [Option<TaskSlot<C>>; TASKS],
    cursor: usize,
    live: usize,
}

struct TaskSlot<C> {
    run: TaskFn<C>,
    state: TaskState,
}

impl<C, const TASKS: usize> Scheduler<C, TASKS> {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; TASKS],
            cursor: 0,
            live: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        TASKS
    }

    pub const fn len(&self) -> usize {
        self.live
    }

    pub const fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub const fn is_full(&self) -> bool {
        self.live == TASKS
    }

    pub fn spawn(&mut self, run: TaskFn<C>) -> Result<(), SpawnError> {
        self.spawn_with_state(run, TaskState::new())
    }

    pub fn spawn_with_state(&mut self, run: TaskFn<C>, state: TaskState) -> Result<(), SpawnError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(SpawnError::Full)?;
        *slot = Some(TaskSlot { run, state });
        self.live += 1;
        Ok(())
    }

    /// Runs at most one task, searching from the round-robin cursor.
    pub fn run_one(&mut self, context: &mut C) -> RunOutcome {
        if self.live == 0 {
            return RunOutcome::Idle;
        }

        for _ in 0..TASKS {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % TASKS;

            let poll = match self.slots[index].as_mut() {
                Some(slot) => (slot.run)(context, &mut slot.state),
                None => continue,
            };

            return match poll {
                TaskPoll::Pending => RunOutcome::Pending,
                TaskPoll::Complete => {
                    self.slots[index] = None;
                    self.live -= 1;
                    RunOutcome::Completed
                }
            };
        }

        // `live` is maintained with the slots, so this is reachable only if a
        // future implementation introduces a non-runnable slot state.
        RunOutcome::Idle
    }

    /// Runs each task that was live at the start of the round at most once.
    pub fn run_round(&mut self, context: &mut C) -> usize {
        let scheduled = self.live;
        for _ in 0..scheduled {
            let _ = self.run_one(context);
        }
        scheduled
    }
}

impl<C, const TASKS: usize> Default for Scheduler<C, TASKS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Context {
        log: [u8; 8],
        len: usize,
    }

    impl Context {
        fn push(&mut self, value: u8) {
            self.log[self.len] = value;
            self.len += 1;
        }
    }

    fn task_one(context: &mut Context, state: &mut TaskState) -> TaskPoll {
        context.push(1);
        let calls = state.get(0).unwrap();
        state.set(0, calls + 1);
        if calls == 0 {
            TaskPoll::Pending
        } else {
            TaskPoll::Complete
        }
    }

    fn task_two(context: &mut Context, state: &mut TaskState) -> TaskPoll {
        context.push(2);
        let calls = state.get(0).unwrap();
        state.set(0, calls + 1);
        if calls == 0 {
            TaskPoll::Pending
        } else {
            TaskPoll::Complete
        }
    }

    #[test]
    fn runs_tasks_round_robin_until_complete() {
        let mut scheduler = Scheduler::<Context, 2>::new();
        let mut context = Context {
            log: [0; 8],
            len: 0,
        };
        scheduler.spawn(task_one).unwrap();
        scheduler.spawn(task_two).unwrap();

        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Pending);
        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Pending);
        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Completed);
        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Completed);
        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Idle);
        assert_eq!(&context.log[..context.len], &[1, 2, 1, 2]);
        assert!(scheduler.is_empty());
    }

    #[test]
    fn enforces_capacity_and_reuses_completed_slots() {
        let mut scheduler = Scheduler::<Context, 1>::new();
        let mut context = Context {
            log: [0; 8],
            len: 0,
        };
        scheduler
            .spawn_with_state(task_one, TaskState::from_words([1, 0, 0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(scheduler.spawn(task_two), Err(SpawnError::Full));

        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Completed);
        assert!(scheduler.spawn(task_two).is_ok());
    }

    #[test]
    fn run_round_invokes_each_live_task_once() {
        let mut scheduler = Scheduler::<Context, 2>::new();
        let mut context = Context {
            log: [0; 8],
            len: 0,
        };
        scheduler.spawn(task_one).unwrap();
        scheduler.spawn(task_two).unwrap();

        assert_eq!(scheduler.run_round(&mut context), 2);
        assert_eq!(&context.log[..context.len], &[1, 2]);
        assert_eq!(scheduler.len(), 2);
    }

    #[test]
    fn zero_capacity_scheduler_stays_idle() {
        let mut scheduler = Scheduler::<Context, 0>::new();
        let mut context = Context {
            log: [0; 8],
            len: 0,
        };

        assert_eq!(scheduler.spawn(task_one), Err(SpawnError::Full));
        assert_eq!(scheduler.run_one(&mut context), RunOutcome::Idle);
    }
}
