use std::mem::MaybeUninit;

use anyhow::anyhow;

#[derive(Debug)]
pub struct Queue<T> {
    data: Vec<MaybeUninit<T>>,
    len: u16,
    cap: u16,
    /// points to the next vacant slot
    head: usize,
    /// points to slot for next pop
    tail: usize,
}

impl<T> Queue<T> {
    pub fn new(cap: usize) -> Self {
        assert!(
            cap <= u16::MAX as usize,
            "queue only supports max u16 elements"
        );
        let mut v = Vec::with_capacity(cap);

        // SAFETY:
        // we are handling uninitialized data anyways and we are not growing the queue cap
        unsafe {
            v.set_len(cap);
        }

        Queue {
            data: v,
            len: 0,
            cap: cap as u16,
            head: 0,
            tail: 0,
        }
    }

    pub fn push(&mut self, elem: T) -> anyhow::Result<()> {
        if self.len == self.cap {
            return Err(anyhow!("queue is full"));
        }
        let i = self.h_idx();

        self.data[i].write(elem);
        self.head += 1;
        self.len += 1;

        Ok(())
    }
    pub fn pop(&mut self) -> Option<T> {
        // tail has to be lower than head
        if self.tail == self.head {
            return None;
        }
        let i = self.t_idx();

        // SAFETY:
        // tail always follows head so data is never uninitialized and
        // never gets called twice on the same element
        let elem = unsafe { self.data[i].assume_init_read() };
        self.tail += 1;
        self.len -= 1;

        Some(elem)
    }
    pub fn peek(&self) -> Option<&T> {
        let i = self.t_idx();

        // tail has to be lower than head
        if self.tail == self.head {
            return None;
        }

        // SAFETY:
        // tail always follows head so data is never uninitialized and
        let elem = unsafe { self.data[i].assume_init_ref() };

        Some(elem)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == self.cap
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn iter(&self) -> QueueRefIter<'_, T> {
        QueueRefIter {
            data: &self.data,
            tail: self.tail,
            cap: self.cap,
            len: self.len,
        }
    }

    fn h_idx(&self) -> usize {
        self.head % self.cap as usize
    }
    fn t_idx(&self) -> usize {
        self.tail % self.cap as usize
    }
}

impl<T> Drop for Queue<T> {
    fn drop(&mut self) {
        if std::mem::needs_drop::<T>() {
            while self.pop().is_some() {}
        }
    }
}

impl<T: Clone> Clone for Queue<T> {
    fn clone(&self) -> Self {
        let mut new = Queue::new(self.cap as usize);

        for i in 0..self.len {
            let idx = (self.tail + i as usize) % new.cap as usize;
            new.push(unsafe { self.data[idx].assume_init_ref().clone() })
                .expect("this cant fail because we only clone over n <= cap elements");
        }
        new
    }
}

impl<T> IntoIterator for Queue<T> {
    type Item = T;

    type IntoIter = QueueIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        QueueIter { q: self }
    }
}

pub struct QueueIter<T> {
    q: Queue<T>,
}

impl<T> Iterator for QueueIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.q.pop()
    }
}

pub struct QueueRefIter<'a, T> {
    data: &'a Vec<MaybeUninit<T>>,
    tail: usize,
    cap: u16,
    len: u16,
}

impl<'a, T> Iterator for QueueRefIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.tail % self.cap as usize;
        if self.tail < self.len as usize {
            // SAFETY:
            // tail always follows head so data is never uninitialized
            let elem = unsafe { self.data[idx].assume_init_ref() };
            self.tail += 1;
            return Some(elem);
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct MyElement(String);

impl Drop for MyElement {
    fn drop(&mut self) {
        println!("i got dropped!");
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_results)]
    use super::*;

    #[test]
    fn queue_test() {
        let mut q = Queue::new(10);
        q.push(MyElement(String::from("hello")));
        q.push(MyElement(String::from("world")));
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop().unwrap(), MyElement(String::from("hello")));
        assert_eq!(q.pop().unwrap(), MyElement(String::from("world")));
        assert!(q.is_empty());
    }
    #[test]
    fn queue_test2() {
        let mut q = Queue::new(10);
        q.push(MyElement(String::from("hello")));
        q.push(MyElement(String::from("world")));

        drop(q);
        println!("no more drops");
    }

    #[test]
    fn queue_test3() {
        let mut q = Queue::new(10);

        for _ in 0..10 {
            q.push(MyElement(String::from("hello")));
        }
        assert!(q.is_full());
        assert!(q.push(MyElement(String::from("hello"))).is_err());

        for _ in 0..10 {
            assert!(q.pop().is_some());
        }
        assert!(q.is_empty());
    }

    #[test]
    fn queue_test_iter() {
        let mut q = Queue::new(10);

        for _ in 0..10 {
            q.push(MyElement(String::from("hello")));
        }
        assert!(q.is_full());
        assert!(q.push(MyElement(String::from("hello"))).is_err());

        let mut iter = q.iter();
        for _ in 0..10 {
            assert!(iter.next().is_some())
        }

        let mut iter = q.into_iter();
        for _ in 0..10 {
            assert!(iter.next().is_some())
        }
        assert!(iter.next().is_none());
    }

    #[test]
    fn queue_test_clone() {
        let mut q = Queue::new(10);

        for _ in 0..10 {
            q.push(MyElement(String::from("hello")));
        }

        let mut clone = q.clone();

        for _ in 0..10 {
            assert!(clone.pop().is_some());
        }
        assert!(clone.is_empty());
    }
}
