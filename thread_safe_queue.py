from queue import Queue, Empty


class ThreadSafeQueue:
    """
    Simple thread-safe queue wrapper.
    """

    def __init__(self, maxsize=0):
        self.queue = Queue(maxsize=maxsize)

    def push(self, item):
        self.queue.put(item)

    def pop(self, timeout=None):
        try:
            return self.queue.get(timeout=timeout)
        except Empty:
            return None

    def task_done(self):
        self.queue.task_done()

    def empty(self):
        return self.queue.empty()

    def size(self):
        return self.queue.qsize()