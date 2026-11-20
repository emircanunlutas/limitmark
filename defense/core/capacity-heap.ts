export class IndexedMinHeap<T> {
  private readonly items: T[] = [];

  constructor(
    private readonly keyOf: (item: T) => number,
    private readonly getIndex: (item: T) => number,
    private readonly setIndex: (item: T, index: number) => void,
  ) {}

  get size(): number {
    return this.items.length;
  }

  peek(): T | null {
    return this.items.length > 0 ? this.items[0] : null;
  }

  push(item: T): void {
    const index = this.items.length;
    this.items.push(item);
    this.setIndex(item, index);
    this.siftUp(index);
  }

  remove(item: T): boolean {
    const index = this.getIndex(item);
    if (index < 0 || index >= this.items.length || this.items[index] !== item) return false;
    const last = this.items.pop()!;
    this.setIndex(item, -1);
    if (index < this.items.length) {
      this.items[index] = last;
      this.setIndex(last, index);
      if (!this.siftUp(index)) this.siftDown(index);
    }
    return true;
  }

  private siftUp(index: number): boolean {
    let moved = false;
    let i = index;
    while (i > 0) {
      const parent = (i - 1) >>> 1;
      if (this.keyOf(this.items[i]) >= this.keyOf(this.items[parent])) break;
      this.swap(i, parent);
      i = parent;
      moved = true;
    }
    return moved;
  }

  private siftDown(index: number): void {
    let i = index;
    const n = this.items.length;
    while (true) {
      const left = (i << 1) + 1;
      const right = left + 1;
      let smallest = i;
      if (left < n && this.keyOf(this.items[left]) < this.keyOf(this.items[smallest])) smallest = left;
      if (right < n && this.keyOf(this.items[right]) < this.keyOf(this.items[smallest])) smallest = right;
      if (smallest === i) break;
      this.swap(i, smallest);
      i = smallest;
    }
  }

  private swap(a: number, b: number): void {
    const tmp = this.items[a];
    this.items[a] = this.items[b];
    this.items[b] = tmp;
    this.setIndex(this.items[a], a);
    this.setIndex(this.items[b], b);
  }
}

