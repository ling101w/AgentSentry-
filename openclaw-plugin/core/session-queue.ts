/** Serializes asynchronous work for one session without blocking other sessions. */
export class SessionQueue {
  private readonly tails = new Map<string, Promise<void>>();

  has(key: string): boolean {
    return this.tails.has(key);
  }

  run<T>(key: string, work: () => T | Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const result = previous.then(work);
    const tail = result.then(() => undefined, () => undefined);
    this.tails.set(key, tail);
    void tail.then(() => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    });
    return result;
  }
}
